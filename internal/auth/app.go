package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"swjtu-cli/internal/config"
)

const (
	// AppBaseURL 是扬华小智 App 的后端（与一网通办同域）。
	AppBaseURL = "https://i.swjtu.edu.cn"
	// AppExchangePath 用 CAS mobile_code 换 accessToken。
	AppExchangePath = "/swjtu/frontend/app-login/exchangeRsa"

	appDefaultUA = "ZhilinEai ZhilinSwjtuApp/1.0.7 swjtu-cli Android 16"
)

// appSessionExpiredCodes 是服务端返回的会话失效错误码。
// 10013 是通用登录失效，4600400 是 App 登录态失效。
var appSessionExpiredCodes = map[int]bool{10013: true, 4600400: true}

// AppUserAgent 返回 App 请求头 User-Agent。
// 服务端按 UA 分流：缺少 "ZhilinEai ZhilinSwjtuApp/" 前缀会被当作非 App 请求。
// 可用 SWJTU_CLI_APP_UA 覆盖（例如需要模拟特定机型时）。
func AppUserAgent() string {
	if v := strings.TrimSpace(os.Getenv("SWJTU_CLI_APP_UA")); v != "" {
		return v
	}
	return appDefaultUA
}

// AppClient 是扬华小智 App 接口客户端。
// 所有请求都是 form 编码的 RSA 密文 + authorization-str 请求头。
type AppClient struct {
	BaseURL string // 为空时使用 AppBaseURL（测试可指向 httptest）
	HTTP    *http.Client
	Session *config.AppSession
	DryRun  bool // 只返回将要发送的参数，不发请求
}

func (c *AppClient) baseURL() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return AppBaseURL
}

// NewAppClient 载入已保存的 App 会话。
// 没有 App 会话但本地 CAS 会话（统一会话或旧 App cookie）可用时，
// 静默用 CAS cookie 换一个 accessToken——不提交密码、不发短信，
// 实现"一次登录，处处可用"。CAS TGC 也失效时才要求重新登录。
func NewAppClient() (*AppClient, error) {
	s, err := config.LoadAppSession()
	if err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	if s == nil || s.AccessToken == "" {
		if !HasCASSession() {
			return nil, &UnauthenticatedError{Msg: "尚未登录扬华小智，请先执行 swjtu app login"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), HTTPTimeout()*4)
		defer cancel()
		if s, err = ReLoginAppFromCAS(ctx); err != nil {
			return nil, err
		}
	}
	jar, _ := cookiejar.New(nil)
	restoreAppCookies(jar, s.Cookies)
	return &AppClient{
		HTTP:    &http.Client{Timeout: HTTPTimeout(), Jar: jar},
		Session: s,
	}, nil
}

type appAuthPayload struct {
	Timestamp int64  `json:"timestamp"`
	Ticket    string `json:"ticket"`
}

type appEnvelope struct {
	E json.RawMessage `json:"e"`
	M string          `json:"m"`
	D json.RawMessage `json:"d"`
}

// Do 调用任意 App 接口。path 可以带查询串（例如 term/app?current_time=…）。
// accessToken 失效时自动走恢复阶梯：用本地 CAS 会话静默换新 token
// （不提交密码、不发短信），成功后重放一次请求；失败保留原始错误。
func (c *AppClient) Do(ctx context.Context, path string, params any) (json.RawMessage, error) {
	data, err := c.doOnce(ctx, path, params)
	if err == nil {
		return data, nil
	}
	var ue *UnauthenticatedError
	if errors.As(err, &ue) && !c.DryRun && HasCASSession() {
		if s, rerr := ReLoginAppFromCAS(ctx); rerr == nil {
			c.Session = s
			if jar, ok := c.HTTP.Jar.(*cookiejar.Jar); ok {
				restoreAppCookies(jar, s.Cookies)
			}
			return c.doOnce(ctx, path, params)
		}
	}
	return nil, err
}

func (c *AppClient) doOnce(ctx context.Context, path string, params any) (json.RawMessage, error) {
	if c.Session == nil {
		return nil, &UnauthenticatedError{Msg: "尚未登录扬华小智，请先执行 swjtu app login"}
	}
	if params == nil {
		params = map[string]any{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("序列化请求参数失败: %w", err)
	}
	if c.DryRun {
		return json.RawMessage(raw), nil
	}
	content, err := appEncrypt(raw)
	if err != nil {
		return nil, err
	}
	authJSON, err := json.Marshal(appAuthPayload{
		Timestamp: time.Now().UnixMilli(),
		Ticket:    c.Session.AccessToken,
	})
	if err != nil {
		return nil, err
	}
	authStr, err := appEncrypt(authJSON)
	if err != nil {
		return nil, err
	}
	data, err := c.post(ctx, path, content, authStr)
	c.persistCookies()
	return data, err
}

// persistCookies 把响应中新增的 cookie 写回会话。
// App 的 /me 等接口依赖 IDS 会话 cookie，而不仅是 accessToken。
func (c *AppClient) persistCookies() {
	if c.Session == nil || c.HTTP == nil {
		return
	}
	jar, ok := c.HTTP.Jar.(*cookiejar.Jar)
	if !ok {
		return
	}
	cookies := collectAppCookies(jar)
	if len(cookies) == 0 {
		return
	}
	c.Session.Cookies = cookies
	_ = config.SaveAppSession(c.Session)
}

func (c *AppClient) post(ctx context.Context, path, content, authStr string) (json.RawMessage, error) {
	form := url.Values{}
	form.Set("content", content)
	fullURL := c.baseURL() + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", "zh-Hans-CN;q=1, en-CN;q=0.9")
	req.Header.Set("from-eai", "1")
	req.Header.Set("authorization-str", authStr)
	req.Header.Set("User-Agent", AppUserAgent())
	debugRequest(http.MethodPost, fullURL, c.Session.AccessToken)

	status, _, body, err := Do(ctx, c.HTTP, req)
	if err != nil {
		if se, ok := err.(*ServiceError); ok {
			se.StatusCode = status
		}
		return nil, err
	}
	return parseAppEnvelope(status, body)
}

func parseAppEnvelope(status int, body []byte) (json.RawMessage, error) {
	var env appEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, &ServiceError{StatusCode: status, Msg: "响应不是 JSON: " + snippet(body)}
	}
	code, _ := appErrorCode(env.E)
	switch {
	case code == 0:
		return decodeAppData(env.D)
	case appSessionExpiredCodes[code]:
		msg := strings.TrimSpace(env.M)
		if msg == "" {
			msg = "App 会话已失效，请重新执行 swjtu app login"
		}
		return nil, &UnauthenticatedError{Msg: msg}
	default:
		msg := strings.TrimSpace(env.M)
		if msg == "" {
			msg = fmt.Sprintf("App 接口返回错误码 %d", code)
		}
		return nil, &ServiceError{StatusCode: status, Msg: msg}
	}
}

func appErrorCode(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return 0, nil
		}
		var v int
		if _, err := fmt.Sscanf(s, "%d", &v); err == nil {
			return v, nil
		}
	}
	return 0, fmt.Errorf("无法解析错误码 %s", string(raw))
}

func decodeAppData(d json.RawMessage) (json.RawMessage, error) {
	if len(d) == 0 || string(d) == "null" {
		return json.RawMessage("null"), nil
	}
	var s string
	if err := json.Unmarshal(d, &s); err == nil {
		plain, err := appDecrypt(s)
		if err != nil {
			return nil, &ServiceError{Msg: err.Error()}
		}
		if !json.Valid(plain) {
			return nil, &ServiceError{Msg: "响应解密后不是 JSON: " + snippet(plain)}
		}
		return json.RawMessage(plain), nil
	}
	return d, nil
}

// appCookieURLs 覆盖 App 与 CAS 的常见 path，用于收集/恢复 cookie。
var appCookieURLs = []string{
	AppBaseURL + "/",
	AppBaseURL + "/swjtu/",
	AppBaseURL + "/swjtu/frontend/",
	casBaseURL + "/",
	casBaseURL + "/authserver/",
}

func cookieURLFor(c config.HTTPCookie) string {
	domain := strings.ToLower(c.Domain)
	switch {
	case strings.Contains(domain, "cas.swjtu.edu.cn"):
		return casBaseURL + "/"
	case strings.Contains(domain, "i.swjtu.edu.cn"):
		return AppBaseURL + "/"
	}
	// host-only cookie：CAS 常见 cookie 名优先回 CAS，其余回 i.swjtu。
	switch strings.ToLower(c.Name) {
	case "castgc", "jsessionid", "route", "happyvoyage", "platformmultilingual":
		return casBaseURL + "/"
	default:
		return AppBaseURL + "/"
	}
}

func restoreAppCookies(jar *cookiejar.Jar, cookies []config.HTTPCookie) {
	if jar == nil {
		return
	}
	for _, ck := range cookies {
		u, err := url.Parse(cookieURLFor(ck))
		if err != nil {
			continue
		}
		jar.SetCookies(u, []*http.Cookie{{
			Name: ck.Name, Value: ck.Value, Path: ck.Path, Domain: ck.Domain,
			Expires: ck.Expires, Secure: ck.Secure, HttpOnly: ck.HttpOnly,
		}})
	}
}

func collectAppCookies(jar *cookiejar.Jar) []config.HTTPCookie {
	if jar == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []config.HTTPCookie
	for _, raw := range appCookieURLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for _, ck := range jar.Cookies(u) {
			domain := ck.Domain
			if domain == "" {
				domain = u.Hostname()
			}
			key := ck.Name + "|" + domain + "|" + ck.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, config.HTTPCookie{
				Name: ck.Name, Value: ck.Value, Path: ck.Path, Domain: domain,
				Expires: ck.Expires, Secure: ck.Secure, HttpOnly: ck.HttpOnly,
			})
		}
	}
	return out
}

// ExchangeAppLogin 用 CAS mobile_code 换取 App accessToken 并保存会话。
// cookies 是 CAS 登录过程中获得的会话 cookie（/app-login/me 需要 IDS 会话）。
func ExchangeAppLogin(ctx context.Context, mobileCode, deviceID string, cookies []config.HTTPCookie) (*config.AppSession, error) {
	if strings.TrimSpace(mobileCode) == "" {
		return nil, &LoginError{Msg: "mobile_code 为空"}
	}
	if strings.TrimSpace(deviceID) == "" {
		deviceID = NewUUID()
	}
	payload := struct {
		MobileCode string `json:"mobileCode"`
		DeviceID   string `json:"device_id"`
		SID        string `json:"sid"`
		MobileType string `json:"mobile_type"`
	}{
		MobileCode: mobileCode,
		DeviceID:   deviceID,
		SID:        deviceID,
		MobileType: "android",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	content, err := appEncrypt(raw)
	if err != nil {
		return nil, err
	}
	authJSON, err := json.Marshal(appAuthPayload{Timestamp: time.Now().UnixMilli(), Ticket: ""})
	if err != nil {
		return nil, err
	}
	authStr, err := appEncrypt(authJSON)
	if err != nil {
		return nil, err
	}

	jar, _ := cookiejar.New(nil)
	restoreAppCookies(jar, cookies)
	c := &AppClient{
		HTTP:    &http.Client{Timeout: HTTPTimeout(), Jar: jar},
		Session: &config.AppSession{},
	}
	form := url.Values{}
	form.Set("content", content)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, AppBaseURL+AppExchangePath, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", "zh-Hans-CN;q=1, en-CN;q=0.9")
	req.Header.Set("from-eai", "1")
	req.Header.Set("authorization-str", authStr)
	req.Header.Set("User-Agent", AppUserAgent())

	status, _, body, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	data, err := parseAppEnvelope(status, body)
	if err != nil {
		return nil, err
	}
	var d struct {
		AccessToken string          `json:"accessToken"`
		User        json.RawMessage `json:"user"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, &ServiceError{Msg: "exchangeRsa 响应结构异常: " + snippet(data)}
	}
	if strings.TrimSpace(d.AccessToken) == "" {
		return nil, &LoginError{Msg: "exchangeRsa 未返回 accessToken: " + snippet(data)}
	}
	s := &config.AppSession{
		AccessToken: d.AccessToken,
		User:        d.User,
		LoginTime:   time.Now().Unix(),
		DeviceID:    deviceID,
		Cookies:     collectAppCookies(jar),
	}
	if err := config.SaveAppSession(s); err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	return s, nil
}
