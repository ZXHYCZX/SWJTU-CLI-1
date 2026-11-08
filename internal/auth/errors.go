package auth

import "fmt"

// UnauthenticatedError 表示会话失效（401），触发自动重登并重放一次。
type UnauthenticatedError struct{ Msg string }

func (e *UnauthenticatedError) Error() string {
	if e.Msg == "" {
		return "会话已失效，请重新登录"
	}
	return e.Msg
}

// LoginError 表示登录阶段失败（账号密码错误、账号被锁等），不应重试。
type LoginError struct{ Msg string }

func (e *LoginError) Error() string { return e.Msg }

// CaptchaError 表示验证码获取/提交失败。
type CaptchaError struct{ Msg string }

func (e *CaptchaError) Error() string { return e.Msg }

// ServiceError 表示服务端/网络错误，不触发重登。
type ServiceError struct {
	StatusCode int
	Msg        string
}

func (e *ServiceError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("服务端错误（HTTP %d）: %s", e.StatusCode, e.Msg)
	}
	return e.Msg
}

// IsUnauthenticated 供 cli 层映射错误 kind。
func IsUnauthenticated(err error) bool {
	_, ok := err.(*UnauthenticatedError)
	return ok
}
