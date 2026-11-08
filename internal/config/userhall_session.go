package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// UserHallSession 是办事大厅（userhall）的派生会话：
// cookie 由 CAS ticket 静默链换取（不注销 SSO），Token 是 API 请求头
// 需要的 Captcha-Token。
type UserHallSession struct {
	Cookies   []HTTPCookie `json:"cookies"`
	Token     string       `json:"token"`
	LoginTime int64        `json:"login_time"`
}

func userHallSessionPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "userhall_session.json"), nil
}

// LoadUserHallSession 读取办事大厅会话；文件不存在返回 (nil, nil)。
func LoadUserHallSession() (*UserHallSession, error) {
	path, err := userHallSessionPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取办事大厅会话失败: %w", err)
	}
	var s UserHallSession
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("办事大厅会话文件损坏（%s）: %w", path, err)
	}
	return &s, nil
}

// SaveUserHallSession 原子写入办事大厅会话（0600）。
func SaveUserHallSession(s *UserHallSession) error {
	return savePrivateJSON(userHallSessionPath, s)
}

// ClearUserHallSession 删除办事大厅会话。
func ClearUserHallSession() error {
	return removeIfExists(userHallSessionPath)
}
