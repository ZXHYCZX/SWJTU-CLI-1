package auth

import (
	"context"
	"net/http/cookiejar"
	"net/url"
	"time"

	"swjtu-cli/internal/config"
)

// 本文件实现 CAS 会话的二次认证（reAuth）升级。
//
// 背景：浏览器登录（或长时间未认证）的 CAS 会话对敏感 service 会强制
// 二次认证（reAuthLoginView）。完成一次 reAuth 后会话信任级别提升，
// 之后所有 service ticket 都能静默签发（与密码+短信登录的会话同级）。
//
// 流程复用 app login 的二次认证机制：
//   1. StartCASReAuth：打开 reAuthLoginView（service 用 CAS 移动端服务），
//      解析认证页参数并存入待认证状态，随后可调用 RequestAppMFACode 发短信；
//   2. CompleteCASReAuth：提交验证码（内部即 CompleteAppLogin），
//      成功后顺带刷新 App accessToken 与统一 CAS 会话。

// StartCASReAuth 对当前 CAS 会话发起二次认证。
// 返回的 challenge 描述要求的认证方式；CLI 层随后调用
// RequestAppMFACode（发短信）与 CompleteCASReAuth（提交验证码）。
func StartCASReAuth(ctx context.Context) (*AppMFAChallenge, error) {
	bridge, err := LoadCASBridge()
	if err != nil {
		return nil, err
	}
	jar, ok := bridge.Client().Jar.(*cookiejar.Jar)
	if !ok {
		return nil, &LoginError{Msg: "CAS 会话桥 cookie 状态异常"}
	}
	reAuthURL := casBaseURL + "/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true&service=" +
		url.QueryEscape(casMobileService)
	_, _, body, err := HTTPGet(ctx, bridge.Client(), reAuthURL)
	if err != nil {
		return nil, err
	}
	if !isReAuthPage(reAuthURL, body) {
		// 会话本就不需要二次认证（可能刚完成过）
		return nil, &LoginError{Msg: "当前 CAS 会话不需要二次认证"}
	}
	p := parseReAuthPage(reAuthURL, body)
	if p.ReAuthType == "" {
		return nil, &LoginError{Msg: "二次认证页解析失败：未找到 reAuthType"}
	}
	p.Service = casMobileService
	p.Cookies = jarCookies(jar, casBaseURL+"/")
	p.CreatedAt = time.Now().Unix()
	if err := config.SaveAppPendingLogin(p); err != nil {
		return nil, &config.ConfigError{Msg: err.Error()}
	}
	return &AppMFAChallenge{
		Type:         mfaTypeLabel(p.ReAuthType),
		ReAuthType:   p.ReAuthType,
		Phone:        pPhone(body),
		Alternatives: reauthAlternatives(body),
	}, nil
}

// CompleteCASReAuth 提交二次认证验证码，升级 CAS 会话信任级别。
// 成功后 App accessToken 一并刷新（复用 CompleteAppLogin 的完整链路）。
func CompleteCASReAuth(ctx context.Context, code string) (*config.AppSession, error) {
	return CompleteAppLogin(ctx, code)
}
