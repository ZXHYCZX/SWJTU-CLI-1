package auth

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"swjtu-cli/internal/config"
)

// 本文件实现"登录桥"：把本地保存的 CAS 会话（CASTGC/TGC）当作万能钥匙，
// 为任何接入 CAS 的系统静默签发 service ticket / mobile_code。
//
// 恢复阶梯（全部不提交密码、不发送短信，无风控风险）：
//   1. 业务 token 有效         -> 直接用
//   2. 业务 token 失效         -> CAS cookie 换新 ticket / mobile_code
//   3. CAS TGC 失效            -> 用户重新登录（app login 或 auth login --browser）

// HasCASSession 快速判断本地是否存有 CAS 会话（不做网络请求）。
// 优先看统一 CAS 会话，回退看 App 会话里的 CAS cookie。
func HasCASSession() bool {
	if s, err := config.LoadAuthSession(); err == nil && s != nil && len(s.Cookies) > 0 {
		return true
	}
	if app, err := config.LoadAppSession(); err == nil && app != nil && len(filterCASCookies(app.Cookies)) > 0 {
		return true
	}
	return false
}

// CasBridge 持有一份 CAS 会话 cookie，能对任意 service 签发 ticket。
type CasBridge struct {
	Cookies []config.HTTPCookie
	client  *http.Client
	Session *config.AuthSession // cookie 来源（可能由 App 会话回退合成）
}

// LoadCASBridge 载入可用的 CAS 会话桥。
// 没有任何 CAS 凭据时返回 UnauthenticatedError（提示先登录）。
func LoadCASBridge() (*CasBridge, error) {
	if s, err := config.LoadAuthSession(); err == nil && s != nil && len(s.Cookies) > 0 {
		return newCasBridge(s), nil
	}
	app, err := config.LoadAppSession()
	if err == nil && app != nil {
		cas := filterCASCookies(app.Cookies)
		if len(cas) > 0 {
			s := &config.AuthSession{
				Cookies:    cas,
				Method:     "app-login",
				LoggedInAt: app.LoginTime,
			}
			return newCasBridge(s), nil
		}
	}
	return nil, &UnauthenticatedError{Msg: "本地没有可用的 CAS 会话，请先执行 swjtu auth login 或 swjtu app login"}
}

func newCasBridge(s *config.AuthSession) *CasBridge {
	client := NewBaseClient()
	jar, _ := cookiejar.New(nil)
	restoreAppCookies(jar, s.Cookies)
	client.Jar = jar
	return &CasBridge{
		Cookies: s.Cookies,
		Session: s,
		client:  client,
	}
}

// Client 返回装载了 CAS cookie 的 HTTP client（不跟随重定向）。
func (b *CasBridge) Client() *http.Client { return b.client }

// Alive 探测 CAS 会话是否仍然有效：带 cookie GET 登录页，
// 出现登录表单（pwdEncryptSalt）说明 TGC 已失效。
// 只读 GET，不提交任何凭据，无风控风险。
func (b *CasBridge) Alive(ctx context.Context) (bool, error) {
	_, _, body, err := HTTPGet(ctx, b.client, casLogin)
	if err != nil {
		return false, err
	}
	return !strings.Contains(string(body), "pwdEncryptSalt"), nil
}

// ServiceTicket 为任意 service URL 签发一次性 CAS ticket。
// 用户可能粘进来不带 scheme 的地址（如 yhxt.swjtu.edu.cn/xxx），这里补全。
func (b *CasBridge) ServiceTicket(ctx context.Context, service string) (string, error) {
	service = normalizeServiceURL(service)
	if service == "" {
		return "", &LoginError{Msg: "service URL 无效"}
	}
	return casServiceTicket(ctx, b.client, service)
}

// MobileCode 为扬华小智 App 签发 mobile_code（CAS 移动端入口）。
func (b *CasBridge) MobileCode(ctx context.Context) (string, error) {
	status, header, _, err := HTTPGet(ctx, b.client, CASMobileAuthURL)
	if err != nil {
		return "", err
	}
	if code := mobileCodeFromURL(CASMobileAuthURL); code != "" {
		return code, nil
	}
	pageURL := CASMobileAuthURL
	for i := 0; i < 10 && status >= 300 && status < 400; i++ {
		loc := header.Get("Location")
		if loc == "" {
			break
		}
		if code := mobileCodeFromURL(loc); code != "" {
			return code, nil
		}
		if !strings.HasPrefix(loc, "http") {
			loc = casBaseURL + loc
		}
		pageURL = loc
		status, header, _, err = HTTPGet(ctx, b.client, pageURL)
		if err != nil {
			return "", err
		}
		if code := mobileCodeFromURL(loc); code != "" {
			return code, nil
		}
	}
	_, _, body, gerr := HTTPGet(ctx, b.client, casLogin)
	if gerr == nil {
		s := string(body)
		if strings.Contains(s, "reAuthLoginView") || strings.Contains(s, "isMultifactor") ||
			strings.Contains(s, "二次认证") {
			return "", &UnauthenticatedError{Msg: "CAS 要求二次认证，请先执行 swjtu auth reauth（发送短信验证码升级会话）"}
		}
		if strings.Contains(s, "pwdEncryptSalt") {
			return "", &UnauthenticatedError{Msg: "CAS 会话已失效，请重新执行 swjtu auth login（或 swjtu app login）"}
		}
	}
	return "", &LoginError{Msg: "CAS 未返回 mobile_code（回跳链异常），请重新执行 swjtu auth login"}
}

// ReLoginAppFromCAS 用本地 CAS 会话静默换取新的 App accessToken。
// 不提交密码、不发短信；CAS TGC 失效时返回 UnauthenticatedError。
// 成功后 App 会话与统一 CAS 会话均被刷新。
func ReLoginAppFromCAS(ctx context.Context) (*config.AppSession, error) {
	bridge, err := LoadCASBridge()
	if err != nil {
		return nil, err
	}
	code, err := bridge.MobileCode(ctx)
	if err != nil {
		return nil, err
	}
	return exchangeWithDevice(ctx, code, bridge.Session.Username, "cas-refresh", bridge.Cookies)
}

// filterCASCookies 只保留 CAS 域的 cookie（CASTGC/TGC 等）。
func filterCASCookies(cookies []config.HTTPCookie) []config.HTTPCookie {
	var out []config.HTTPCookie
	for _, ck := range cookies {
		domain := strings.ToLower(ck.Domain)
		if strings.Contains(domain, "cas.swjtu.edu.cn") {
			out = append(out, ck)
			continue
		}
		switch strings.ToLower(ck.Name) {
		case "castgc", "tgc":
			out = append(out, ck)
		}
	}
	return out
}

// persistAuthSession 在任何一次登录完成（拿到 mobile_code）后刷新统一 CAS 会话。
// 失败不影响登录结果（best effort）。
func persistAuthSession(username, method string, cookies []config.HTTPCookie) {
	_ = config.MergeAuthSession(username, method, cookies)
}

// normalizeServiceURL 补全 https:// 前缀并校验（ticket 调试入口常用裸域名）。
func normalizeServiceURL(service string) string {
	service = strings.TrimSpace(service)
	if service == "" {
		return ""
	}
	if !strings.Contains(service, "://") {
		service = "https://" + service
	}
	if _, err := url.Parse(service); err != nil {
		return ""
	}
	return service
}
