package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CardSession 是一卡通服务大厅的派生会话（cookie 由 SSO 链静默换取）。
type CardSession struct {
	Cookies   []HTTPCookie `json:"cookies"`
	LoginTime int64        `json:"login_time"`
}

func cardSessionPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "card_session.json"), nil
}

// LoadCardSession 读取一卡通会话；文件不存在返回 (nil, nil)。
func LoadCardSession() (*CardSession, error) {
	path, err := cardSessionPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取一卡通会话失败: %w", err)
	}
	var s CardSession
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("一卡通会话文件损坏（%s）: %w", path, err)
	}
	return &s, nil
}

// SaveCardSession 原子写入一卡通会话（0600）。
func SaveCardSession(s *CardSession) error {
	return savePrivateJSON(cardSessionPath, s)
}

// ClearCardSession 删除一卡通会话。
func ClearCardSession() error {
	return removeIfExists(cardSessionPath)
}
