package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	casBaseURL = "https://cas.swjtu.edu.cn"
	casLogin   = casBaseURL + "/authserver/login"
	// yhxtService 是扬华学堂在 CAS 注册的 service 地址，
	// 登录成功后 CAS 会 302 到该地址并附 ticket。
	yhxtService = "https://yhxt.swjtu.edu.cn/cas-login.html"
)

// CampusLoginURL 是一网通办（i.swjtu.edu.cn）的 CAS 回跳入口：
// 访问它会 302 到 CAS 登录页（service 指回本地址），登录成功后
// CAS 带 ticket 回跳，i.swjtu 校验 ticket 并建立会话 cookie。
var CampusLoginURL = "https://i.swjtu.edu.cn/manage/common/cas_login/30001?to_bind=0&redirect=" +
	url.QueryEscape("https://i.swjtu.edu.cn/schedule/frontend/default/index")

// CASMobileAuthURL 是 CAS 移动端认证入口（扬华小智 App 使用），
// SSO 会话存在时直接 302 到 default.html#mobile_code=xxx。
var CASMobileAuthURL = casBaseURL + "/authserver/mobile/auth?appId=1442090678600208384"

// CaptchaProvider 描述验证码的获取与求解方式。
type CaptchaProvider interface {
	// Solve 拉取验证码图片并返回识别/人工输入的结果。
	Solve(ctx context.Context, client *http.Client, imageBytes []byte) (string, error)
}

// CASResult 是一次通用 CAS 登录流的产物。
type CASResult struct {
	FinalURL       string           // 登录后重定向链的最终落点（可能是带 ticket 的 service 地址）
	Jar            *cookiejar.Jar   // 整个过程的 cookie（含目标系统的会话）
	TicketLocations []string        // 重定向链上所有带 ticket= 的 Location
}

var (
	reSalt      = regexp.MustCompile(`id="pwdEncryptSalt"\s+value="([^"]*)"`)
	reExecution = regexp.MustCompile(`name="execution"\s+value="([^"]*)"`)
	reLT        = regexp.MustCompile(`name="lt"\s+value="([^"]*)"`)
	reErrMsg    = regexp.MustCompile(`(?is)<span[^>]*id="(?:msg|showErrorTip)"[^>]*>(.*?)</span>`)
	reMobileCode = regexp.MustCompile(`mobile_code=([A-Za-z0-9]+)`)
)

// casLoginFlow 是通用 CAS 登录流：
//  1. GET startURL 并手动跟随 302 直到 200 页面；
//  2. 若页面是登录表单（含 pwdEncryptSalt）则解析并提交（密码 AES、验证码按需）；
//  3. 登录成功后继续跟随 302 链直到 200，期间记录带 ticket 的 Location。
//
// 登录失败（页面重新渲染错误信息）返回 LoginError。
func casLoginFlow(ctx context.Context, username, password, startURL string, captchaProvider CaptchaProvider) (*CASResult, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := NewBaseClient()
	client.Jar = jar

	// 1. 从 startURL 走到登录页；pageURL 始终记录「产生当前 body 的 URL」。
	//    铁律：提交登录必须 POST 到 pageURL（含 service 等查询参数）——
	//    POST 到裸 /authserver/login 会让 webflow 的 checkAuthorizedAccess
	//    状态 NPE（HTTP 500），且服务端把这类中断计入失败次数（触发账号冻结）。
	pageURL := startURL
	status, header, body, err := HTTPGet(ctx, client, pageURL)
	if err != nil {
		return nil, err
	}
	res := &CASResult{Jar: jar}
	tickets := []string{}

	// 若 SSO 已放行，直接走到业务页；否则会落在登录表单页
	if salt := firstGroup(reSalt, body); salt == "" {
		// 不是登录页：跟随重定向链找登录页或直接结束
		for i := 0; i < 8 && status >= 300 && status < 400; i++ {
			loc := header.Get("Location")
			if loc == "" {
				break
			}
			if strings.Contains(loc, "ticket=") {
				tickets = append(tickets, loc)
			}
			if code := firstGroup(reMobileCode, []byte(loc)); code != "" {
				res.FinalURL = loc
				res.TicketLocations = tickets
				return res, nil
			}
			if !strings.HasPrefix(loc, "http") {
				loc = casBaseURL + loc
			}
			pageURL = loc
			status, header, body, err = HTTPGet(ctx, client, pageURL)
			if err != nil {
				return nil, err
			}
		}
	}

	salt := firstGroup(reSalt, body)
	if salt == "" {
		// 没有登录表单：视为已登录（SSO 放行），直接返回落点
		res.FinalURL = currentURL(status, header, body, startURL)
		res.TicketLocations = tickets
		return res, nil
	}
	execution := firstGroup(reExecution, body)
	lt := firstGroup(reLT, body)
	if execution == "" {
		return nil, &ServiceError{Msg: "登录页解析失败：未找到 execution，认证平台可能已改版"}
	}

	// 2. 探测验证码（连续失败后被置位）
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
	// 注意：lt 为空时必须整体省略——提交空字符串会让 CAS webflow 抛
	// NullPointerException（checkAuthorizedAccess 状态，实测回归确认）。
	if lt != "" {
		form.Set("lt", lt)
	}

	if needCaptcha {
		_, _, capBytes, err := HTTPGet(ctx, client, casBaseURL+"/authserver/getCaptcha.htl?"+fmt.Sprint(time.Now().UnixMilli()))
		if err != nil {
			return nil, &CaptchaError{Msg: fmt.Sprintf("获取验证码图片失败: %v", err)}
		}
		if captchaProvider == nil {
			return nil, &CaptchaError{Msg: "本次登录需要验证码（该账号近期登录失败过多），请在终端交互登录或用 --captcha 传入"}
		}
		code, err := captchaProvider.Solve(ctx, client, capBytes)
		if err != nil {
			return nil, &CaptchaError{Msg: err.Error()}
		}
		form.Set("captcha", code)
	}

	// 3. 提交登录并沿 302 链走到业务页。
	//    铁律：POST 目标是登录页的完整 URL（pageURL，含 service），
	//    不是裸 /authserver/login（丢 service 会 NPE 并计入失败次数）。
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
		if strings.Contains(loc, "ticket=") {
			tickets = append(tickets, loc)
		}
		if code := firstGroup(reMobileCode, []byte(loc)); code != "" {
			res.FinalURL = loc
			res.TicketLocations = tickets
			return res, nil
		}
		if !strings.HasPrefix(loc, "http") {
			loc = casBaseURL + loc
		}
		status, header, body, err = HTTPGet(ctx, client, loc)
		if err != nil {
			return nil, err
		}
	}

	// 登录失败：页面重新渲染并带错误信息
	if msg := extractLoginError(body); msg != "" {
		return nil, &LoginError{Msg: msg}
	}
	if len(tickets) == 0 {
		return nil, &LoginError{Msg: fmt.Sprintf("登录未成功（HTTP %d）: %s", status, snippet(body))}
	}
	res.FinalURL = lastLocation(header, body)
	res.TicketLocations = tickets
	return res, nil
}

func currentURL(status int, header http.Header, body []byte, fallback string) string {
	if loc := header.Get("Location"); loc != "" {
		return loc
	}
	return fallback
}

func lastLocation(header http.Header, body []byte) string {
	if loc := header.Get("Location"); loc != "" {
		return loc
	}
	return ""
}

// DownloadCaptcha 独立下载一张验证码图片到 path（仅供人工查看，与登录会话不绑定）。
func DownloadCaptcha(ctx context.Context, path string) error {
	client := NewBaseClient()
	_, _, img, err := HTTPGet(ctx, client, casBaseURL+"/authserver/getCaptcha.htl?"+fmt.Sprint(time.Now().UnixMilli()))
	if err != nil {
		return err
	}
	return os.WriteFile(path, img, 0o600)
}

// extractLoginError 从登录失败页面提取错误信息（去 HTML 标签）。
func extractLoginError(body []byte) string {
	m := reErrMsg.FindSubmatch(body)
	if m == nil {
		return ""
	}
	s := string(m[1])
	s = strings.TrimSpace(regexp.MustCompile(`(?s)<[^>]*>`).ReplaceAllString(s, ""))
	return s
}

func firstGroup(re *regexp.Regexp, b []byte) string {
	m := re.FindSubmatch(b)
	if m == nil {
		return ""
	}
	return string(m[1])
}

func snippet(b []byte) string {
	s := string(b)
	if len(s) > 800 {
		s = s[:800]
	}
	return s
}
