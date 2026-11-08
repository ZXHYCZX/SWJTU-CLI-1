//go:build manual

package auth

import (
	"context"
	"testing"
	"time"

	"swjtu-cli/internal/config"
)

// TestLiveStartAppLogin 只跑到二次认证页，不发送短信、不提交验证码。
// 运行：go test ./internal/auth -tags manual -run TestLiveStartAppLogin -v
func TestLiveStartAppLogin(t *testing.T) {
	creds, err := config.LoadCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if creds == nil || creds.Username == "" || creds.Password == "" {
		t.Skip("no saved credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := StartAppLogin(ctx, creds.Username, creds.Password, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if out.Session != nil {
		t.Logf("login completed without MFA; user=%s", string(out.Session.User))
		return
	}
	if out.MFA == nil {
		t.Fatal("neither session nor MFA")
	}
	t.Logf("MFA required: type=%s reauthType=%s phone=%s alternatives=%v",
		out.MFA.Type, out.MFA.ReAuthType, out.MFA.Phone, out.MFA.Alternatives)
}

// TestLiveSwitchToSMS 只把待认证状态切换到短信（不发送短信、不提交验证码）。
func TestLiveSwitchToSMS(t *testing.T) {
	p, err := config.LoadAppPendingLogin()
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Skip("no pending login")
	}
	if err := changeMFAType(context.Background(), p, "3"); err != nil {
		t.Fatal(err)
	}
	t.Logf("switched to reAuthType=%s", p.ReAuthType)
}

// TestLiveSendSMS 请求发送短信验证码（会真实发短信）。
func TestLiveSendSMS(t *testing.T) {
	ch, err := RequestAppMFACode(context.Background(), "sms")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sms sent: type=%s phone=%s", ch.Type, ch.Phone)
}
