package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AuthSession 是统一 CAS 会话（"万能钥匙"层）。
//
// 只保存 CAS 域的会话 cookie（核心是 CASTGC/TGC）。任何接入 CAS 的系统
// 都可以用它静默签发 service ticket，无需再提交账号密码或触发二次认证：
//
//	CAS cookie ──> login?service=X ──> ST-xxx ──> 目标系统
//
// 产生途径：app login（密码/短信）、auth login --browser（浏览器手动登录）。
type AuthSession struct {
	// Cookies 是 CAS（以及浏览器登录时顺带收集的 *.swjtu.edu.cn）会话 cookie。
	Cookies []HTTPCookie `json:"cookies"`
	// Method 记录最近一次登录方式：password / mfa / browser / cas-refresh。
	Method string `json:"method,omitempty"`
	// Username 是登录学号（浏览器登录时可能取不到，留空）。
	Username string `json:"username,omitempty"`
	// LoggedInAt 是最近一次完整登录的 Unix 秒（静默续期不刷新）。
	LoggedInAt int64 `json:"logged_in_at"`
}

func authSessionPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "auth_session.json"), nil
}

// LoadAuthSession 读取统一 CAS 会话；文件不存在返回 (nil, nil)。
func LoadAuthSession() (*AuthSession, error) {
	path, err := authSessionPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取统一 CAS 会话失败: %w", err)
	}
	var s AuthSession
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("统一 CAS 会话文件损坏（%s）: %w", path, err)
	}
	return &s, nil
}

// SaveAuthSession 原子写入统一 CAS 会话（0600）。
func SaveAuthSession(s *AuthSession) error {
	return savePrivateJSON(authSessionPath, s)
}

// ClearAuthSession 删除统一 CAS 会话。
func ClearAuthSession() error {
	return removeIfExists(authSessionPath)
}

// MergeAuthSession 用新 cookie/信息更新统一会话（保留旧 method/username）：
//   - cookies 非空时整体覆盖（CAS cookie 以最新为准）；
//   - username/method 非空且非 cas-refresh 时才覆盖记录；
//   - cas-refresh（静默续期）不刷新 LoggedInAt，保留真实登录时间。
func MergeAuthSession(username, method string, cookies []HTTPCookie) error {
	s, err := LoadAuthSession()
	if err != nil {
		s = nil
	}
	if s == nil {
		s = &AuthSession{}
	}
	if len(cookies) > 0 {
		s.Cookies = cookies
	}
	if username != "" {
		s.Username = username
	}
	if method != "" && method != "cas-refresh" {
		s.Method = method
		s.LoggedInAt = time.Now().Unix()
	}
	if s.LoggedInAt == 0 {
		s.LoggedInAt = time.Now().Unix()
	}
	return SaveAuthSession(s)
}
