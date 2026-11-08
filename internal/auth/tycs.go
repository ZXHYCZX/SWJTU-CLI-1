package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"swjtu-cli/internal/config"
)

// TycsBaseURL 是交大体测系统的 API 前缀。
const TycsBaseURL = "https://tycs.swjtu.edu.cn/prod-api"

// tycsCallbackService 是体测系统在 CAS 注册的 service（sso-url 动态返回）。
const tycsCallbackService = "https://tycs.swjtu.edu.cn/prod-api/casService/cas/callback"

// TycsClient 是交大体测系统客户端。
// token 由 CAS ticket 换取（静默，无需密码），过期后自动用 CAS 会话续期。
type TycsClient struct {
	HTTP  *http.Client
	Token string
	User  json.RawMessage
}

// NewTycsClient 构造体测客户端；本地没有 CAS 会话时返回错误。
func NewTycsClient() (*TycsClient, error) {
	if !HasCASSession() {
		return nil, &UnauthenticatedError{Msg: "尚未登录，请先执行 swjtu auth login 或 swjtu app login"}
	}
	c := &TycsClient{HTTP: NewBaseClient()}
	if sess, err := config.LoadTycsSession(); err == nil && sess != nil && !sess.Expired(time.Now().Unix()) {
		c.Token = sess.Token
		c.User = sess.User
	}
	return c, nil
}

// EnsureToken 保证持有有效 token；过期时静默换新。
func (c *TycsClient) EnsureToken(ctx context.Context) error {
	if c.Token != "" {
		return nil
	}
	return c.refreshToken(ctx)
}

// refreshToken 用本地 CAS 会话静默换新体测 token。
func (c *TycsClient) refreshToken(ctx context.Context) error {
	bridge, err := LoadCASBridge()
	if err != nil {
		return err
	}
	ticket, err := bridge.ServiceTicket(ctx, tycsCallbackService)
	if err != nil {
		return err
	}
	return c.loginWithTicket(ctx, ticket)
}

func (c *TycsClient) loginWithTicket(ctx context.Context, ticket string) error {
	body := strings.NewReader(fmt.Sprintf(`{"ticket":%q}`, ticket))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TycsBaseURL+"/casService/cas/login", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "swjtu-cli")
	status, _, resp, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return err
	}
	var env struct {
		Code    string `json:"code"`
		Message string `json:"msg"`
		Data    struct {
			Token string          `json:"token"`
			User  json.RawMessage `json:"user,omitempty"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &env); err != nil {
		return &ServiceError{StatusCode: status, Msg: "体测登录响应解析失败: " + snippet(resp)}
	}
	if env.Code != "0000" || env.Data.Token == "" {
		return &ServiceError{StatusCode: status, Msg: firstNonEmpty(env.Message, "体测登录失败（code="+env.Code+"）")}
	}
	c.Token = env.Data.Token
	sess := &config.TycsSession{Token: c.Token, LoginTime: time.Now().Unix()}
	if len(env.Data.User) > 0 {
		c.User = env.Data.User
		sess.User = env.Data.User
	}
	_ = config.SaveTycsSession(sess)
	return nil
}

// Do 发起带认证的 GET 请求并解析统一包层；401 时静默续期重放一次。
func (c *TycsClient) Do(ctx context.Context, path string, params map[string]any) (json.RawMessage, error) {
	data, err := c.doTry(ctx, path, params)
	if err == nil {
		return data, nil
	}
	if !IsUnauthenticated(err) {
		return nil, err
	}
	c.Token = ""
	if rerr := c.refreshToken(ctx); rerr != nil {
		return nil, err
	}
	return c.doTry(ctx, path, params)
}

func (c *TycsClient) doTry(ctx context.Context, path string, params map[string]any) (json.RawMessage, error) {
	full := TycsBaseURL + path
	if len(params) > 0 {
		q := urlValuesFromMap(params)
		if q != "" {
			full += "?" + q
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	status, _, resp, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, &UnauthenticatedError{}
	}
	var env struct {
		Code    string          `json:"code"`
		Message string          `json:"msg"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(resp, &env); err != nil {
		return nil, &ServiceError{StatusCode: status, Msg: "响应不是 JSON: " + snippet(resp)}
	}
	if env.Code != "0000" {
		return nil, &ServiceError{StatusCode: status, Msg: firstNonEmpty(env.Message, "体测接口返回 code="+env.Code)}
	}
	return env.Data, nil
}

// CurrentUser 查询当前用户（顺便缓存 userId 等信息）。
func (c *TycsClient) CurrentUser(ctx context.Context) (json.RawMessage, error) {
	if len(c.User) > 0 {
		return c.User, nil
	}
	data, err := c.Do(ctx, "/userCenter/user/current", nil)
	if err != nil {
		return nil, err
	}
	c.User = data
	if sess, err := config.LoadTycsSession(); err == nil && sess != nil {
		sess.User = data
		_ = config.SaveTycsSession(sess)
	}
	return data, nil
}

// urlValuesFromMap 把 string/int 参数拼成 query（体测接口参数都是简单类型）。
func urlValuesFromMap(m map[string]any) string {
	var b strings.Builder
	first := true
	for k, v := range m {
		if v == nil {
			continue
		}
		var s string
		switch x := v.(type) {
		case string:
			s = x
		case int:
			s = fmt.Sprint(x)
		case int64:
			s = fmt.Sprint(x)
		case float64:
			s = fmt.Sprint(int64(x))
		default:
			continue
		}
		if !first {
			b.WriteByte('&')
		}
		first = false
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(s)
	}
	return b.String()
}
