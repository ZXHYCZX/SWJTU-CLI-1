// Package config 管理本地凭据与配置。凭据明文保存在用户配置目录的
// credentials.json（0600），写入为原子替换。
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TokenTTLSeconds 是无 exp 信息时的兜底会话时长（与前端 UI 一致）。
// 注意：扬华学堂实际签发的是约 7 天的 JWT，能用 exp 时以 exp 为准，
// 避免不必要的重新登录（CAS 登录频次过高会触发风控）。
const TokenTTLSeconds = 2 * 60 * 60

// expMargin 提前 5 分钟视为过期，留出请求时间。
const expMargin = 300

// ConfigError 表示本地配置读写失败。
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return e.Msg }

// Credentials 是持久化的登录凭据与会话 token。
type Credentials struct {
	Username  string          `json:"username"`
	Password  string          `json:"password"`
	Token     string          `json:"token"`
	LoginTime int64           `json:"login_time"` // Unix 秒
	UserInfo  json.RawMessage `json:"user_info,omitempty"`
}

// jwtExp 从 JWT 的 payload 中解析 exp（Unix 秒）；非 JWT 返回 0。
func jwtExp(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return 0
	}
	return claims.Exp
}

// Expired 判断会话是否已失效：优先用 JWT 的 exp，其次 2 小时兜底。
func (c *Credentials) Expired(now int64) bool {
	if c.Token == "" {
		return true
	}
	if exp := jwtExp(c.Token); exp > 0 {
		return now >= exp-expMargin
	}
	return now-c.LoginTime >= TokenTTLSeconds
}

// ConfigDir 返回配置目录，可被 SWJTU_CLI_CONFIG_DIR 覆盖（测试必须用它隔离）。
func ConfigDir() (string, error) {
	if dir := os.Getenv("SWJTU_CLI_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("获取用户配置目录失败: %w", err)
	}
	return filepath.Join(base, "swjtu-cli"), nil
}

func credentialsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

// LoadCredentials 读取凭据；文件不存在返回 (nil, nil)。
func LoadCredentials() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取凭据失败: %w", err)
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("凭据文件损坏（%s）: %w", path, err)
	}
	return &c, nil
}

// SaveCredentials 原子写入凭据（0600）。
func SaveCredentials(c *Credentials) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "credentials.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("写入凭据失败: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("保存凭据失败: %w", err)
	}
	return nil
}

// ClearCredentials 删除凭据文件；文件不存在不视为错误。
func ClearCredentials() error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// CookieStore 是按 URL 分组的持久化 cookie 集合（一网通办会话）。
type CookieStore struct {
	URLs map[string][]HTTPCookie `json:"urls"`
}

// HTTPCookie 是可 JSON 序列化的 http.Cookie 子集。
type HTTPCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path,omitempty"`
	Domain   string    `json:"domain,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	HttpOnly bool      `json:"http_only,omitempty"`
}

func cookiesPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cookies.json"), nil
}

// SaveCookies 原子写入 cookie 集合。
func SaveCookies(store *CookieStore) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	path, err := cookiesPath()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// LoadCookies 读取 cookie 集合；文件不存在返回 (nil, nil)。
func LoadCookies() (*CookieStore, error) {
	path, err := cookiesPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var store CookieStore
	if err := json.Unmarshal(b, &store); err != nil {
		return nil, fmt.Errorf("cookie 文件损坏（%s）: %w", path, err)
	}
	return &store, nil
}

// ClearCookies 删除 cookie 文件。
func ClearCookies() error {
	path, err := cookiesPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
