package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AppSession 是扬华小智 App 的登录会话。
//
// access_token 在服务端实际被当作长期 ticket 使用：App 每次请求都用它生成
// authorization-str 请求头，而不是标准 OAuth 的 Bearer token。
type AppSession struct {
	AccessToken string          `json:"access_token"`
	User        json.RawMessage `json:"user,omitempty"`
	LoginTime   int64           `json:"login_time"` // Unix 秒
	DeviceID    string          `json:"device_id,omitempty"`
	// Cookies 是登录过程中 CAS / i.swjtu 下发的会话 cookie。
	// App 的 /app-login/me 等接口依赖 IDS 会话，仅有 accessToken 不够。
	Cookies []HTTPCookie `json:"cookies,omitempty"`
}

// AppPendingLogin 是 CAS 二次认证的中间状态。
//
// 只保存 CAS 会话 cookie 与认证页参数，绝不保存账号密码。验证码提交成功后
// 立即删除。
type AppPendingLogin struct {
	Cookies       []HTTPCookie `json:"cookies"`
	ReAuthURL     string       `json:"reauth_url"`
	Username      string       `json:"username"`
	Service       string       `json:"service"`
	ReAuthType    string       `json:"reauth_type"`
	IsMultifactor string       `json:"is_multifactor"`
	UserID        string       `json:"user_id,omitempty"`
	MFAType       string       `json:"mfa_type,omitempty"`
	MFAFailures   int          `json:"mfa_failures,omitempty"`
	CreatedAt     int64        `json:"created_at"`
}

// AppPendingTTL 是待二次认证状态的有效期。
const AppPendingTTL = 10 * time.Minute

func appSessionPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "app_session.json"), nil
}

func appPendingPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "app_login_pending.json"), nil
}

// LoadAppSession 读取扬华小智会话；文件不存在返回 (nil, nil)。
func LoadAppSession() (*AppSession, error) {
	path, err := appSessionPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取 App 会话失败: %w", err)
	}
	var s AppSession
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("App 会话文件损坏（%s）: %w", path, err)
	}
	return &s, nil
}

// SaveAppSession 原子写入扬华小智会话（0600）。
func SaveAppSession(s *AppSession) error {
	return savePrivateJSON(appSessionPath, s)
}

// ClearAppSession 删除扬华小智会话。
func ClearAppSession() error {
	return removeIfExists(appSessionPath)
}

// LoadAppPendingLogin 读取待二次认证状态；文件不存在或已过期返回 (nil, nil)。
func LoadAppPendingLogin() (*AppPendingLogin, error) {
	path, err := appPendingPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取待认证状态失败: %w", err)
	}
	var p AppPendingLogin
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("待认证状态文件损坏（%s）: %w", path, err)
	}
	if p.CreatedAt > 0 && time.Since(time.Unix(p.CreatedAt, 0)) > AppPendingTTL {
		_ = ClearAppPendingLogin()
		return nil, nil
	}
	return &p, nil
}

// SaveAppPendingLogin 原子写入待二次认证状态（0600）。
func SaveAppPendingLogin(p *AppPendingLogin) error {
	return savePrivateJSON(appPendingPath, p)
}

// ClearAppPendingLogin 删除待二次认证状态。
func ClearAppPendingLogin() error {
	return removeIfExists(appPendingPath)
}

func savePrivateJSON(pathFn func() (string, error), v any) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	path, err := pathFn()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("写入会话失败: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("保存会话失败: %w", err)
	}
	return nil
}

func removeIfExists(pathFn func() (string, error)) error {
	path, err := pathFn()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
