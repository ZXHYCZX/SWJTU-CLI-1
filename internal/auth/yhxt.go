package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"swjtu-cli/internal/config"
)

// YhxtBaseURL 是扬华学堂（yhxt.swjtu.edu.cn）的 API 前缀。
const YhxtBaseURL = "https://yhxt.swjtu.edu.cn/yethan"

// YhxtClient 是扬华学堂的认证客户端。
//
// token 不再通过账号密码登录获得，而是复用 App 登录时保存的 CAS 会话：
// GET CAS login?service=yhxt -> ticket -> /yethan/public/casCallback -> ytoken。
type YhxtClient struct {
	HTTP     *http.Client
	Token    string
	UserInfo json.RawMessage
}

// NewYhxtClient 构造客户端；本地没有任何 CAS 凭据时返回错误。
// ytoken 在首次请求时经 EnsureToken 静默取得。
func NewYhxtClient() (*YhxtClient, error) {
	if !HasCASSession() {
		return nil, &UnauthenticatedError{Msg: "尚未登录，请先执行 swjtu auth login 或 swjtu app login"}
	}
	c := &YhxtClient{HTTP: NewBaseClient()}
	if sess, err := config.LoadYhxtSession(); err == nil && sess != nil {
		c.Token = sess.Token
		c.UserInfo = sess.UserInfo
	}
	return c, nil
}

// EnsureToken 保证 client 持有未过期的 yhxt token。
// 过期时用 App 会话里的 CAS cookie 换新 ticket，不提交账号密码。
func (c *YhxtClient) EnsureToken(ctx context.Context) error {
	now := time.Now().Unix()
	if sess, err := config.LoadYhxtSession(); err == nil && sess != nil && !sess.Expired(now) {
		if c.Token == "" || c.Token == sess.Token {
			c.Token = sess.Token
			c.UserInfo = sess.UserInfo
			return nil
		}
	}
	sess, err := loginYhxtWithAppCAS(ctx)
	if err != nil {
		return err
	}
	c.Token = sess.Token
	c.UserInfo = sess.UserInfo
	return nil
}

// sanitizeYhxtUserInfo 只保留 CLI 需要的身份字段，避免把密码散列等
// 敏感信息写进 yhxt_session.json。
func sanitizeYhxtUserInfo(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	keep := map[string]bool{
		"passId": true, "userName": true, "collegeCode": true,
		"collegeName": true, "deptCode": true, "roleId": true,
	}
	out := map[string]any{}
	for k, v := range m {
		if keep[k] {
			out[k] = v
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// refreshToken 强制重新换 token（服务端 401 时使用）。
func (c *YhxtClient) refreshToken(ctx context.Context) error {
	sess, err := loginYhxtWithAppCAS(ctx)
	if err != nil {
		return err
	}
	c.Token = sess.Token
	c.UserInfo = sess.UserInfo
	return nil
}

// casCookieSource 按优先级返回可用的 CAS 会话 cookie：
// 1) 统一 CAS 会话（auth_session.json，auth login / app login 都会写）
// 2) 旧 App 会话里的 CAS cookie（向后兼容）
func casCookieSource() ([]config.HTTPCookie, error) {
	if s, err := config.LoadAuthSession(); err == nil && s != nil && len(s.Cookies) > 0 {
		return s.Cookies, nil
	}
	app, err := config.LoadAppSession()
	if err == nil && app != nil && len(app.Cookies) > 0 {
		return app.Cookies, nil
	}
	return nil, &UnauthenticatedError{Msg: "本地没有可用的 CAS 会话，请先执行 swjtu auth login 或 swjtu app login"}
}

// loginYhxtWithAppCAS 用本地 CAS cookie 静默换 yhxt token。
// 命名沿用旧实现：只读 CAS 会话换 ticket，不涉及任何账号密码。
func loginYhxtWithAppCAS(ctx context.Context) (*config.YhxtSession, error) {
	cookies, err := casCookieSource()
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	restoreAppCookies(jar, cookies)
	client := NewBaseClient()
	client.Jar = jar

	ticket, err := casServiceTicket(ctx, client, yhxtService)
	if err != nil {
		// 兼容 App 应用市场里的新入口 service。
		if _, ok := err.(*LoginError); ok {
			ticket, err = casServiceTicket(ctx, client, "https://yhxt.swjtu.edu.cn/yethan/public/cas/jwh5")
		}
		if err != nil {
			return nil, err
		}
	}
	data, err := exchangeTicket(ctx, ticket)
	if err != nil {
		return nil, err
	}
	sess := &config.YhxtSession{
		Token:     data.Token,
		LoginTime: time.Now().Unix(),
		UserInfo:  sanitizeYhxtUserInfo(data.UserInfo),
	}
	if err := config.SaveYhxtSession(sess); err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	return sess, nil
}

// casServiceTicket 在已有 CAS SSO 会话时，为 service 取一张 ticket。
func casServiceTicket(ctx context.Context, client *http.Client, service string) (string, error) {
	pageURL := casLogin + "?service=" + url.QueryEscape(service)
	status, header, body, err := HTTPGet(ctx, client, pageURL)
	if err != nil {
		return "", err
	}
	for i := 0; i < 10 && status >= 300 && status < 400; i++ {
		loc := header.Get("Location")
		if loc == "" {
			break
		}
		if u, err := url.Parse(loc); err == nil {
			if t := u.Query().Get("ticket"); t != "" {
				return t, nil
			}
		}
		if !strings.HasPrefix(loc, "http") {
			loc = casBaseURL + loc
		}
		status, header, body, err = HTTPGet(ctx, client, loc)
		if err != nil {
			return "", err
		}
	}
	s := string(body)
	// 注意：二次认证页（reAuthLoginView）同样包含 pwdEncryptSalt，
	// 必须先识别 reAuth，否则"需要二次认证"会被误报成"会话已失效"。
	if strings.Contains(s, "reAuthLoginView") || strings.Contains(s, "isMultifactor") ||
		strings.Contains(s, "二次认证") {
		return "", &UnauthenticatedError{Msg: "CAS 要求二次认证，请先执行 swjtu auth reauth（发送短信验证码升级会话）"}
	}
	if strings.Contains(s, "pwdEncryptSalt") {
		return "", &UnauthenticatedError{Msg: "CAS 会话已失效，请重新执行 swjtu auth login（或 swjtu app login）"}
	}
	return "", &LoginError{Msg: fmt.Sprintf("CAS 未签发扬华学堂 ticket（HTTP %d）", status)}
}

// casCallbackData 是 casCallback 响应 data：token + 其余用户信息。
type casCallbackData struct {
	Token    string
	UserInfo json.RawMessage
}

// exchangeTicket 用 CAS ticket 换扬华学堂 ytoken。
// 对应网页端流程：浏览器先 GET cas-login.html?ticket=（建立 yhxt 会话 cookie），
// 页面 JS 再调 GET /yethan/public/casCallback?ticket=。
func exchangeTicket(ctx context.Context, ticket string) (*casCallbackData, error) {
	client := NewBaseClient()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client.Jar = jar
	// 1. 先按浏览器行为加载 service 页面，建立 yhxt 侧会话（cookie jar）
	serviceURL := "https://yhxt.swjtu.edu.cn/cas-login.html?ticket=" + url.QueryEscape(ticket)
	_, _, _, _ = HTTPGet(ctx, client, serviceURL)

	// 2. 用同一 cookie jar 调 casCallback
	api := YhxtBaseURL + "/public/casCallback?ticket=" + url.QueryEscape(ticket)
	_, _, body, err := HTTPGet(ctx, client, api)
	if err != nil {
		return nil, err
	}
	var env struct {
		Code    json.RawMessage `json:"code"`
		Status  *bool           `json:"status"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, &ServiceError{Msg: fmt.Sprintf("casCallback 响应解析失败（%v）: %s", err, snippet(body))}
	}
	if env.Status != nil && !*env.Status {
		return nil, &LoginError{Msg: "ticket 换取 token 失败: " + env.Message}
	}
	var d struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil || d.Token == "" {
		return nil, &ServiceError{Msg: fmt.Sprintf("casCallback 未返回 token，code=%s message=%q data=%s",
			string(env.Code), env.Message, snippet(env.Data))}
	}
	return &casCallbackData{Token: d.Token, UserInfo: env.Data}, nil
}

// yhxtEnvelope 是扬华学堂的统一响应包层。
// 成功：{"code":"00000","data":...}；未认证：{"code":401,"message":"未认证，请先登录"}。
// code 可能是字符串或数字，用 any 接收。
type yhxtEnvelope struct {
	Code    any             `json:"code"`
	Status  *bool           `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// DoAPI 发起需要认证的 GET API 请求；参数经 SM2 加密包装进 _j（官方前端协议）。
// 401 时重登一次并重放。
func (c *YhxtClient) DoAPI(ctx context.Context, path string, params map[string]any) (json.RawMessage, error) {
	data, err := c.doAPITry(ctx, path, params)
	if err == nil {
		return data, nil
	}
	if !IsUnauthenticated(err) {
		return nil, err
	}
	// 统一恢复边界：认证失效 → 用 App CAS 会话换新 token → 重放一次
	c.Token = ""
	if err := c.refreshToken(ctx); err != nil {
		return nil, err
	}
	return c.doAPITry(ctx, path, params)
}

// buildJ 构造 _j 参数：{"_t":毫秒,"_d":params} → JSON → SM2(C1C3C2) → hex。
// 对应官方前端 request 拦截器：GET 请求只携带 _j，原参数全部收进 _d。
func buildJ(params map[string]any) (string, error) {
	payload := map[string]any{
		"_t": time.Now().UnixMilli(),
		"_d": params,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return SM2EncryptHex(b)
}

// DoAPIPost 发起需要认证的 POST 请求。
// 与 GET 相同的协议：JSON 体 {"_j": SM2({"_t":…,"_d":params})}。
// 401 时重登一次并重放。
func (c *YhxtClient) DoAPIPost(ctx context.Context, path string, params map[string]any) (json.RawMessage, error) {
	data, err := c.doPostTry(ctx, path, params)
	if err == nil {
		return data, nil
	}
	if !IsUnauthenticated(err) {
		return nil, err
	}
	c.Token = ""
	if err := c.refreshToken(ctx); err != nil {
		return nil, err
	}
	return c.doPostTry(ctx, path, params)
}

func (c *YhxtClient) doPostTry(ctx context.Context, path string, params map[string]any) (json.RawMessage, error) {
	j, err := buildJ(params)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"_j": j})
	if err != nil {
		return nil, err
	}
	full := YhxtBaseURL + path
	debugRequest("POST", full, c.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, full, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ytoken", c.Token)
	status, _, respBody, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, &UnauthenticatedError{}
	}
	return ParseYhxtEnvelope(status, respBody)
}

// DoAPIPostRaw 发起 POST 请求，body 为调用方给定的原始 JSON（探测/调试用）。
func (c *YhxtClient) DoAPIPostRaw(ctx context.Context, path string, bodyJSON []byte) (json.RawMessage, error) {
	full := YhxtBaseURL + path
	debugRequest("POST", full, c.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, full, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ytoken", c.Token)
	status, _, respBody, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, &UnauthenticatedError{}
	}
	return ParseYhxtEnvelope(status, respBody)
}

func (c *YhxtClient) doAPITry(ctx context.Context, path string, params map[string]any) (json.RawMessage, error) {
	j, err := buildJ(params)
	if err != nil {
		return nil, err
	}
	full := YhxtBaseURL + path + "?_j=" + url.QueryEscape(j)
	debugRequest("GET", full, c.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	req.Header.Set("ytoken", c.Token)
	status, _, respBody, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, &UnauthenticatedError{}
	}
	return ParseYhxtEnvelope(status, respBody)
}

// PublicClient 用于免登录的公开接口（/public/*）。
type PublicClient struct{ HTTP *http.Client }

// NewPublicClient 构造免登录客户端。
func NewPublicClient() *PublicClient { return &PublicClient{HTTP: NewBaseClient()} }

// GetJSON 请求公开接口并解析统一包层，返回 data 字段。
// 公开接口实测接受明文 query 参数，无需 _j 包装。
func (c *PublicClient) GetJSON(ctx context.Context, path string, params map[string]any) (json.RawMessage, error) {
	full := YhxtBaseURL + path
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, fmt.Sprint(v))
		}
		full += "?" + q.Encode()
	}
	status, _, respBody, err := HTTPGet(ctx, c.HTTP, full)
	if err != nil {
		return nil, err
	}
	return ParseYhxtEnvelope(status, respBody)
}

// ParseYhxtEnvelope 解析扬华学堂统一响应包层。
// 成功：{"code":"00000","data":...}；未认证：{"code":401,"message":"未认证，请先登录"}。
func ParseYhxtEnvelope(status int, body []byte) (json.RawMessage, error) {
	var env yhxtEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, &ServiceError{StatusCode: status, Msg: fmt.Sprintf("响应不是 JSON（%v）: %s", err, snippet(body))}
	}
	switch code := normalizeCode(env.Code); code {
	case "", "00000", "0":
		// 成功，继续检查 status
	default:
		if code == "401" {
			return nil, &UnauthenticatedError{}
		}
		return nil, &ServiceError{StatusCode: status, Msg: env.Message}
	}
	if env.Status != nil && !*env.Status {
		return nil, &ServiceError{StatusCode: status, Msg: env.Message}
	}
	return env.Data, nil
}

// normalizeCode 把 code（字符串或数字）规整为无小数点的字符串。
func normalizeCode(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return ""
	}
}
