package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"swjtu-cli/internal/config"
)

const (
	appID            = "1442090678600208384"
	casMobileAuthURL = casBaseURL + "/authserver/mobile/auth?appId=" + appID
	// casMobileService 是 App 专属 CAS service；其它 service 签发的 code 不能用于 exchangeRsa。
	casMobileService = casBaseURL + "/authserver/mobile/callback?appId=" + appID + "&login_type=mobileLogin"
)

var (
	reReAuthType    = regexp.MustCompile(`"reAuthType"\s*:\s*"([^"]*)"`)
	reIsMultifactor = regexp.MustCompile(`"isMultifactor"\s*:\s*"([^"]*)"`)
	reReAuthService = regexp.MustCompile(`"service"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	reReAuthUserID  = regexp.MustCompile(`"reAuthUserId"\s*:\s*"([^"]*)"`)
	reMFAPhone   = regexp.MustCompile(`1\d{2}\*{4}\d{4}`)
	reSwitchType = regexp.MustCompile(`switchReAuthType\(\s*['"]([^'"]+)['"]`)
)

// AppMFAChallenge 描述 CAS 二次认证的要求。
type AppMFAChallenge struct {
	Type         string   `json:"type"` // sms / otp / 其它方式的说明
	ReAuthType   string   `json:"reauth_type"`
	Phone        string   `json:"phone,omitempty"`
	Alternatives []string `json:"alternatives,omitempty"`
}

// AppLoginOutcome 是登录第一步的结果：要么已拿到会话，要么停在二次认证。
type AppLoginOutcome struct {
	Session *config.AppSession
	MFA     *AppMFAChallenge
}

// StartAppLogin 用学号密码登录 CAS 移动端 service。
// 若直接拿到 mobile_code 会立即 exchangeRsa 并返回会话；
// 若进入二次认证，则把 CAS cookie 与认证页参数写入 app_login_pending.json。
func StartAppLogin(ctx context.Context, username, password string, provider CaptchaProvider, force bool) (*AppLoginOutcome, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := NewBaseClient()
	client.Jar = jar

	pageURL := casMobileAuthURL
	status, header, body, err := HTTPGet(ctx, client, pageURL)
	if err != nil {
		return nil, err
	}

	// SSO 已放行时直接会带 mobile_code
	if code := mobileCodeFromURL(pageURL); code != "" {
		s, err := exchangeWithDevice(ctx, code, username, "password", jarCookies(jar, casBaseURL+"/"))
		return &AppLoginOutcome{Session: s}, err
	}

	// 跟随重定向到登录页（或直接到二次认证页）
	for i := 0; i < 10 && status >= 300 && status < 400; i++ {
		loc := header.Get("Location")
		if loc == "" {
			break
		}
		if code := mobileCodeFromURL(loc); code != "" {
			s, err := exchangeWithDevice(ctx, code, username, "password", jarCookies(jar, casBaseURL+"/"))
			return &AppLoginOutcome{Session: s}, err
		}
		if !strings.HasPrefix(loc, "http") {
			loc = casBaseURL + loc
		}
		pageURL = loc
		status, header, body, err = HTTPGet(ctx, client, pageURL)
		if err != nil {
			return nil, err
		}
		if isReAuthPage(pageURL, body) {
			return beginMFA(pageURL, body, username, jar)
		}
	}

	salt := firstGroup(reSalt, body)
	if salt == "" {
		if isReAuthPage(pageURL, body) {
			return beginMFA(pageURL, body, username, jar)
		}
		return nil, &LoginError{Msg: "未找到登录表单（CAS 页面可能已改版）: " + snippet(body)}
	}
	execution := firstGroup(reExecution, body)
	lt := firstGroup(reLT, body)
	if execution == "" {
		return nil, &LoginError{Msg: "登录页解析失败：未找到 execution"}
	}

	needCaptcha := false
	if _, _, data, err := HTTPGet(ctx, client, casBaseURL+"/authserver/checkNeedCaptcha.htl?username="+url.QueryEscape(username)); err == nil {
		needCaptcha = strings.Contains(string(data), `"isNeed":true`)
	}

	form := url.Values{}
	form.Set("username", username)
	encPwd, err := EncryptPassword(password, salt)
	if err != nil {
		return nil, err
	}
	form.Set("password", encPwd)
	form.Set("_eventId", "submit")
	form.Set("cllt", "userNameLogin")
	form.Set("dllt", "generalLogin")
	form.Set("rememberMe", "false")
	form.Set("execution", execution)
	if lt != "" {
		form.Set("lt", lt)
	}
	if needCaptcha {
		_, _, capBytes, err := HTTPGet(ctx, client, casBaseURL+"/authserver/getCaptcha.htl?"+fmt.Sprint(time.Now().UnixMilli()))
		if err != nil {
			return nil, &CaptchaError{Msg: fmt.Sprintf("获取验证码图片失败: %v", err)}
		}
		if provider == nil {
			return nil, &CaptchaError{Msg: "本次登录需要验证码，请在终端交互登录或用 --captcha 传入"}
		}
		code, err := provider.Solve(ctx, client, capBytes)
		if err != nil {
			return nil, &CaptchaError{Msg: err.Error()}
		}
		form.Set("captcha", code)
	}

	// 本地节流：密码提交失败会被 CAS 计入失败次数，连续失败可能冻结账号。
	// CLI 绝不自动重试；用户手动重跑时也用冷却期拦住手滑。
	guard, err := config.LoadAppLoginGuard()
	if err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	if !force {
		if wait := guard.PasswordWait(time.Now()); wait > 0 {
			return nil, &LoginError{Msg: fmt.Sprintf(
				"为避免触发 CAS 风控，%d 秒内不重复提交密码；确认要重试请加 --force",
				int(wait.Seconds())+1)}
		}
	}
	guard.LastPasswordAttempt = time.Now().Unix()
	if err := config.SaveAppLoginGuard(guard); err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pageURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", pageURL)
	req.Header.Set("User-Agent", "swjtu-cli")
	status, header, body, err = Do(ctx, client, req)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 8 && status >= 300 && status < 400; i++ {
		loc := header.Get("Location")
		if loc == "" {
			break
		}
		if code := mobileCodeFromURL(loc); code != "" {
			s, err := exchangeWithDevice(ctx, code, username, "password", jarCookies(jar, casBaseURL+"/"))
			return &AppLoginOutcome{Session: s}, err
		}
		if strings.Contains(loc, "reAuth") || strings.Contains(loc, "multifactor") {
			if !strings.HasPrefix(loc, "http") {
				loc = casBaseURL + loc
			}
			_, _, pageBody, err := HTTPGet(ctx, client, loc)
			if err != nil {
				return nil, err
			}
			return beginMFA(loc, pageBody, username, jar)
		}
		if !strings.HasPrefix(loc, "http") {
			loc = casBaseURL + loc
		}
		pageURL = loc
		status, header, body, err = HTTPGet(ctx, client, pageURL)
		if err != nil {
			return nil, err
		}
		if isReAuthPage(pageURL, body) {
			return beginMFA(pageURL, body, username, jar)
		}
	}

	if isReAuthPage(pageURL, body) {
		return beginMFA(pageURL, body, username, jar)
	}
	if msg := extractLoginError(body); msg != "" {
		return nil, &LoginError{Msg: msg}
	}
	return nil, &LoginError{Msg: fmt.Sprintf("登录未成功（HTTP %d）: %s", status, snippet(body))}
}

func beginMFA(pageURL string, body []byte, username string, jar *cookiejar.Jar) (*AppLoginOutcome, error) {
	p := parseReAuthPage(pageURL, body)
	if p.ReAuthType == "" {
		return nil, &LoginError{Msg: "二次认证页解析失败：未找到 reAuthType"}
	}
	// App 登录固定使用带 login_type=mobileLogin 的 mobile callback service；
	// 认证页里展示的 service 可能省略 login_type。
	p.Service = casMobileService
	if p.IsMultifactor == "" {
		p.IsMultifactor = "true"
	}
	p.Username = username
	p.CreatedAt = time.Now().Unix()
	p.Cookies = jarCookies(jar, casBaseURL+"/")
	if err := config.SaveAppPendingLogin(p); err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	return &AppLoginOutcome{MFA: &AppMFAChallenge{
		Type:         mfaTypeLabel(p.ReAuthType),
		ReAuthType:   p.ReAuthType,
		Phone:        pPhone(body),
		Alternatives: reauthAlternatives(body),
	}}, nil
}

func parseReAuthPage(pageURL string, body []byte) *config.AppPendingLogin {
	p := &config.AppPendingLogin{ReAuthURL: pageURL}
	p.ReAuthType = firstGroup(reReAuthType, body)
	p.IsMultifactor = firstGroup(reIsMultifactor, body)
	p.Service = strings.ReplaceAll(firstGroup(reReAuthService, body), `\/`, "/")
	if p.Service == "" {
		if u, err := url.Parse(pageURL); err == nil {
			p.Service = u.Query().Get("service")
		}
	}
	p.UserID = firstGroup(reReAuthUserID, body)
	return p
}

func isReAuthPage(pageURL string, body []byte) bool {
	if strings.Contains(pageURL, "reAuth") || strings.Contains(pageURL, "multifactor") {
		return true
	}
	s := string(body)
	return strings.Contains(s, "reAuthSubmit") || strings.Contains(s, "isMultifactor") || strings.Contains(s, "二次认证")
}

func mfaTypeLabel(reAuthType string) string {
	switch reAuthType {
	case "3":
		return "sms"
	case "4":
		return "wecom"
	case "10":
		return "otp"
	case "11":
		return "email"
	case "14":
		return "qr"
	default:
		return "unknown"
	}
}

func pPhone(body []byte) string {
	return reMFAPhone.FindString(string(body))
}

func reauthAlternatives(body []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reSwitchType.FindAllSubmatch(body, -1) {
		v := string(m[1])
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// RequestAppMFACode 向 CAS 请求发送短信验证码（reAuthType=3）。
// 对 OTP（reAuthType=10）不发送任何请求，只返回提示。
func RequestAppMFACode(ctx context.Context, mfaType string) (*AppMFAChallenge, error) {
	p, err := config.LoadAppPendingLogin()
	if err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	if p == nil {
		return nil, &LoginError{Msg: "没有待完成的二次认证，请重新执行 swjtu app login"}
	}
	if mfaType == "" {
		mfaType = mfaTypeLabel(p.ReAuthType)
	}
	if mfaType == "otp" && p.ReAuthType != "10" {
		return nil, &LoginError{Msg: "本次二次认证不是动态口令（reAuthType=" + p.ReAuthType + "），请用短信验证码"}
	}
	if mfaType != "sms" {
		p.MFAType = mfaType
		if err := config.SaveAppPendingLogin(p); err != nil {
			return nil, &config.ConfigError{Msg: err.Error()}
		}
		return &AppMFAChallenge{Type: mfaType, ReAuthType: p.ReAuthType}, nil
	}
	if p.ReAuthType != "3" {
		if err := changeMFAType(ctx, p, "3"); err != nil {
			return nil, err
		}
	}

	guard, err := config.LoadAppLoginGuard()
	if err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	if wait := guard.SMSWait(time.Now()); wait > 0 {
		return nil, &LoginError{Msg: fmt.Sprintf(
			"短信发送过于频繁，请 %d 秒后再试", int(wait.Seconds())+1)}
	}

	jar, err := restoreJar(p.Cookies)
	if err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	client := NewBaseClient()
	client.Jar = jar

	form := url.Values{}
	userName := p.UserID
	if userName == "" {
		userName = p.Username
	}
	form.Set("userName", userName)
	form.Set("authCodeTypeName", "reAuthDynamicCodeType")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, casBaseURL+"/authserver/dynamicCode/getDynamicCodeByReauth.do", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Referer", p.ReAuthURL)
	req.Header.Set("User-Agent", "swjtu-cli")
	status, _, body, err := Do(ctx, client, req)
	if err != nil {
		return nil, err
	}
	var res struct {
		Res           string `json:"res"`
		ReturnMessage string `json:"returnMessage"`
		Mobile        string `json:"mobile"`
		CodeTime      int    `json:"codeTime"`
		Code          string `json:"code"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, &ServiceError{StatusCode: status, Msg: "发送验证码响应不是 JSON: " + snippet(body)}
	}
	if res.Res != "success" && res.Res != "other_success" {
		msg := res.ReturnMessage
		if msg == "" {
			msg = fmt.Sprintf("发送验证码失败（res=%s）", res.Res)
		}
		return nil, &ServiceError{StatusCode: status, Msg: msg}
	}
	p.MFAType = "sms"
	if err := config.SaveAppPendingLogin(p); err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	guard.LastSMSSent = time.Now().Unix()
	if err := config.SaveAppLoginGuard(guard); err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	phone := strings.TrimSpace(res.Mobile)
	if phone == "" {
		phone = pPhone(body)
	}
	return &AppMFAChallenge{
		Type:       "sms",
		ReAuthType: p.ReAuthType,
		Phone:      phone,
	}, nil
}

// changeMFAType 复刻 reAuth.js 的 switchReAuthType：把二次认证方式切到 target。
func changeMFAType(ctx context.Context, p *config.AppPendingLogin, target string) error {
	jar, err := restoreJar(p.Cookies)
	if err != nil {
		return &config.ConfigError{Msg: err.Error()}
	}
	client := NewBaseClient()
	client.Jar = jar

	form := url.Values{}
	form.Set("isMultifactor", firstNonEmpty(p.IsMultifactor, "true"))
	form.Set("reAuthType", target)
	form.Set("service", p.Service)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, casBaseURL+"/authserver/reAuthCheck/changeReAuthType.do", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Referer", p.ReAuthURL)
	req.Header.Set("User-Agent", "swjtu-cli")
	status, _, body, err := Do(ctx, client, req)
	if err != nil {
		return err
	}
	var res struct {
		Code any `json:"code"`
		Data struct {
			ReAuthType string `json:"reAuthType"`
		} `json:"data"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return &ServiceError{StatusCode: status, Msg: "切换认证方式响应不是 JSON: " + snippet(body)}
	}
	if fmt.Sprint(res.Code) != "1" || res.Data.ReAuthType != target {
		return &LoginError{Msg: firstNonEmpty(res.Msg, "无法切换到短信认证（服务端拒绝），请改用页面要求的方式")}
	}
	p.ReAuthType = res.Data.ReAuthType
	p.Cookies = jarCookies(jar, casBaseURL+"/")
	if err := config.SaveAppPendingLogin(p); err != nil {
		return &config.ConfigError{Msg: err.Error()}
	}
	return nil
}

// CompleteAppLogin 提交二次认证验证码，换取 mobile_code 并完成 exchangeRsa。
func CompleteAppLogin(ctx context.Context, code string) (*config.AppSession, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, &LoginError{Msg: "验证码为空"}
	}
	p, err := config.LoadAppPendingLogin()
	if err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	if p == nil {
		return nil, &LoginError{Msg: "没有待完成的二次认证（或已超过 10 分钟），请重新执行 swjtu app login"}
	}
	jar, err := restoreJar(p.Cookies)
	if err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	client := NewBaseClient()
	client.Jar = jar

	dynamic, otp := "", ""
	if p.ReAuthType == "10" {
		otp = code
	} else {
		dynamic = code
	}
	form := url.Values{}
	form.Set("service", p.Service)
	form.Set("reAuthType", p.ReAuthType)
	form.Set("isMultifactor", p.IsMultifactor)
	form.Set("password", "")
	form.Set("dynamicCode", dynamic)
	form.Set("uuid", "")
	form.Set("answer1", "")
	form.Set("answer2", "")
	form.Set("otpCode", otp)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, casBaseURL+"/authserver/reAuthCheck/reAuthSubmit.do", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Referer", p.ReAuthURL)
	req.Header.Set("User-Agent", "swjtu-cli")
	status, _, body, err := Do(ctx, client, req)
	if err != nil {
		return nil, err
	}
	var res struct {
		Code string `json:"code"`
		Msg  string `json:"msg"`
	}
	_ = json.Unmarshal(body, &res)
	switch res.Code {
	case "reAuth_success":
		// ok
	case "reAuth_failed", "reAuth_unauthorized":
		p.MFAFailures++
		if p.MFAFailures >= 3 {
			_ = config.ClearAppPendingLogin()
			return nil, &LoginError{Msg: "验证码连续错误 3 次，已放弃本次二次认证；请稍后重新执行 swjtu app login"}
		}
		_ = config.SaveAppPendingLogin(p)
		return nil, &LoginError{Msg: firstNonEmpty(res.Msg, fmt.Sprintf(
			"二次认证验证码错误（第 %d/3 次）", p.MFAFailures))}
	default:
		if strings.Contains(res.Msg, "成功") {
			break
		}
		if status >= 300 && status < 400 {
			break
		}
		return nil, &LoginError{Msg: firstNonEmpty(res.Msg, "二次认证失败: "+snippet(body))}
	}

	mobileCode, err := fetchMobileCode(ctx, client, p.Service)
	if err != nil {
		return nil, err
	}
	s, err := exchangeWithDevice(ctx, mobileCode, firstNonEmpty(p.Username, p.UserID), "mfa", jarCookies(jar, casBaseURL+"/"))
	if err != nil {
		return nil, err
	}
	_ = config.ClearAppPendingLogin()
	return s, nil
}

func fetchMobileCode(ctx context.Context, client *http.Client, service string) (string, error) {
	loginURL := casBaseURL + "/authserver/login?service=" + url.QueryEscape(service)
	status, header, _, err := HTTPGet(ctx, client, loginURL)
	if err != nil {
		return "", err
	}
	if code := mobileCodeFromURL(loginURL); code != "" {
		return code, nil
	}
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
		status, header, _, err = HTTPGet(ctx, client, loc)
		if err != nil {
			return "", err
		}
		if code := mobileCodeFromURL(loc); code != "" {
			return code, nil
		}
	}
	return "", &LoginError{Msg: "二次认证通过，但未取得 mobile_code（CAS 回跳链异常）"}
}

func mobileCodeFromURL(raw string) string {
	return firstGroup(reMobileCode, []byte(raw))
}

// exchangeWithDevice 用 mobile_code 完成 exchangeRsa。
// username/method 顺带写入统一 CAS 会话（method 为 cas-refresh 时不覆盖登录方式记录）。
func exchangeWithDevice(ctx context.Context, mobileCode, username, method string, cookies []config.HTTPCookie) (*config.AppSession, error) {
	deviceID := ""
	if old, err := config.LoadAppSession(); err == nil && old != nil {
		deviceID = old.DeviceID
	}
	if deviceID == "" {
		deviceID = NewUUID()
	}
	s, err := ExchangeAppLogin(ctx, mobileCode, deviceID, cookies)
	if err == nil {
		persistAuthSession(username, method, cookies)
		_ = config.ClearAppLoginGuard()
	}
	return s, err
}

// casCookieURLs 覆盖 CAS 各页面路径。cookiejar 按 path 过滤，
// 只查根路径会漏掉 Path=/authserver 的 JSESSIONID/CASTGC。
var casCookieURLs = []string{
	casBaseURL + "/",
	casBaseURL + "/authserver/",
	casBaseURL + "/authserver/login",
	casBaseURL + "/authserver/reAuthCheck/reAuthLoginView.do",
	casBaseURL + "/authserver/mobile/",
}

func jarCookies(jar *cookiejar.Jar, _ string) []config.HTTPCookie {
	seen := map[string]bool{}
	var out []config.HTTPCookie
	for _, raw := range casCookieURLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for _, ck := range jar.Cookies(u) {
			key := ck.Name + "|" + ck.Domain + "|" + ck.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			domain := ck.Domain
			if domain == "" {
				domain = u.Hostname() // host-only cookie：记录来源域名，便于过滤/展示
			}
			out = append(out, config.HTTPCookie{
				Name: ck.Name, Value: ck.Value, Path: ck.Path, Domain: domain,
				Expires: ck.Expires, Secure: ck.Secure, HttpOnly: ck.HttpOnly,
			})
		}
	}
	return out
}

func restoreJar(cookies []config.HTTPCookie) (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(casBaseURL + "/")
	if err != nil {
		return nil, err
	}
	for _, ck := range cookies {
		jar.SetCookies(u, []*http.Cookie{{
			Name: ck.Name, Value: ck.Value, Path: ck.Path, Domain: ck.Domain,
			Expires: ck.Expires, Secure: ck.Secure, HttpOnly: ck.HttpOnly,
		}})
	}
	return jar, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// NewUUID 生成 RFC 4122 v4 UUID（App 的 device_id/sid 使用同一值）。
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
