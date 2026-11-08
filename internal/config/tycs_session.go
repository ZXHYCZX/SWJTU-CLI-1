package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// TycsSession 是交大体测系统的派生会话：token 由 CAS ticket 换取，
// JWT 自带 exp，过期后用本地 CAS 会话静默续期。
type TycsSession struct {
	Token     string          `json:"token"`
	LoginTime int64           `json:"login_time"`
	User      json.RawMessage `json:"user,omitempty"`
}

func tycsSessionPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tycs_session.json"), nil
}

// LoadTycsSession 读取体测会话；文件不存在返回 (nil, nil)。
func LoadTycsSession() (*TycsSession, error) {
	path, err := tycsSessionPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取体测会话失败: %w", err)
	}
	var s TycsSession
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("体测会话文件损坏（%s）: %w", path, err)
	}
	return &s, nil
}

// SaveTycsSession 原子写入体测会话（0600）。
func SaveTycsSession(s *TycsSession) error {
	return savePrivateJSON(tycsSessionPath, s)
}

// ClearTycsSession 删除体测会话。
func ClearTycsSession() error {
	return removeIfExists(tycsSessionPath)
}

// Expired 优先按 JWT exp 判断，解析不出时回退 12 小时。
func (s *TycsSession) Expired(now int64) bool {
	if s == nil || s.Token == "" {
		return true
	}
	if exp := jwtExp(s.Token); exp > 0 {
		return now >= exp-expMargin
	}
	return now-s.LoginTime >= 12*60*60
}
