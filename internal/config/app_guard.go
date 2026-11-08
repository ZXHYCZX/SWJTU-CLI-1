package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AppLoginGuard 记录本地登录节流状态，避免短时间内反复提交密码触发 CAS 风控。
//
// 这不是安全机制，只是“手滑保护”：CLI 自身不会自动重试密码；
// 用户连续执行 login 时，第二次会被本地冷却拦下。
type AppLoginGuard struct {
	LastPasswordAttempt int64 `json:"last_password_attempt"`
	LastSMSSent         int64 `json:"last_sms_sent"`
}

// AppPasswordCooldown 是两次密码提交之间的最小间隔。
const AppPasswordCooldown = 3 * time.Minute

// AppSMSCooldown 是两次短信请求之间的最小间隔（服务端通常也是 120 秒）。
const AppSMSCooldown = 2 * time.Minute

func appGuardPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "app_login_guard.json"), nil
}

// LoadAppLoginGuard 读取节流状态；文件不存在返回空结构。
func LoadAppLoginGuard() (*AppLoginGuard, error) {
	path, err := appGuardPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &AppLoginGuard{}, nil
		}
		return nil, fmt.Errorf("读取登录节流状态失败: %w", err)
	}
	var g AppLoginGuard
	if err := json.Unmarshal(b, &g); err != nil {
		return &AppLoginGuard{}, nil
	}
	return &g, nil
}

// SaveAppLoginGuard 原子写入节流状态。
func SaveAppLoginGuard(g *AppLoginGuard) error {
	return savePrivateJSON(appGuardPath, g)
}

// ClearAppLoginGuard 删除节流状态（登录成功后调用）。
func ClearAppLoginGuard() error {
	return removeIfExists(appGuardPath)
}

// PasswordWait 返回距离允许再次提交密码的剩余时间。
func (g *AppLoginGuard) PasswordWait(now time.Time) time.Duration {
	if g.LastPasswordAttempt == 0 {
		return 0
	}
	elapsed := now.Sub(time.Unix(g.LastPasswordAttempt, 0))
	if elapsed >= AppPasswordCooldown {
		return 0
	}
	return AppPasswordCooldown - elapsed
}

// SMSWait 返回距离允许再次请求短信的剩余时间。
func (g *AppLoginGuard) SMSWait(now time.Time) time.Duration {
	if g.LastSMSSent == 0 {
		return 0
	}
	elapsed := now.Sub(time.Unix(g.LastSMSSent, 0))
	if elapsed >= AppSMSCooldown {
		return 0
	}
	return AppSMSCooldown - elapsed
}
