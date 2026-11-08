package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// YhxtSession 是扬华学堂（yhxt.swjtu.edu.cn）的派生会话：token 由 App 的
// CAS 会话换 ticket 得到，不再单独提交账号密码。
type YhxtSession struct {
	Token     string          `json:"token"`
	LoginTime int64           `json:"login_time"`
	UserInfo  json.RawMessage `json:"user_info,omitempty"`
}

func yhxtSessionPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "yhxt_session.json"), nil
}

// LoadYhxtSession 读取扬华学堂会话；文件不存在返回 (nil, nil)。
func LoadYhxtSession() (*YhxtSession, error) {
	path, err := yhxtSessionPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取扬华学堂会话失败: %w", err)
	}
	var s YhxtSession
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("扬华学堂会话文件损坏（%s）: %w", path, err)
	}
	return &s, nil
}

// SaveYhxtSession 原子写入扬华学堂会话（0600）。
func SaveYhxtSession(s *YhxtSession) error {
	return savePrivateJSON(yhxtSessionPath, s)
}

// ClearYhxtSession 删除扬华学堂会话。
func ClearYhxtSession() error {
	return removeIfExists(yhxtSessionPath)
}

// Expired 优先按 JWT exp 判断，解析不出时回退 2 小时。
func (s *YhxtSession) Expired(now int64) bool {
	if s == nil || s.Token == "" {
		return true
	}
	if exp := jwtExp(s.Token); exp > 0 {
		return now >= exp-expMargin
	}
	return now-s.LoginTime >= TokenTTLSeconds
}

// User 返回 casCallback 的 user_info（可能为空）。
func (s *YhxtSession) User() json.RawMessage {
	if s == nil {
		return nil
	}
	return s.UserInfo
}

// NowUnix 便于测试。
func NowUnix() int64 { return time.Now().Unix() }
