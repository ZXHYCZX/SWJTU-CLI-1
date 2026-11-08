package config

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAppSessionRoundTrip(t *testing.T) {
	t.Setenv("SWJTU_CLI_CONFIG_DIR", t.TempDir())
	in := &AppSession{
		AccessToken: "token-123",
		User:        json.RawMessage(`{"userId":"2023000000"}`),
		LoginTime:   time.Now().Unix(),
		DeviceID:    "device-1",
	}
	if err := SaveAppSession(in); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAppSession()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.AccessToken != in.AccessToken || got.DeviceID != in.DeviceID {
		t.Fatalf("got %+v", got)
	}
	if err := ClearAppSession(); err != nil {
		t.Fatal(err)
	}
	got, err = LoadAppSession()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil after clear, got %+v", got)
	}
}

func TestAppPendingLoginExpires(t *testing.T) {
	t.Setenv("SWJTU_CLI_CONFIG_DIR", t.TempDir())
	p := &AppPendingLogin{
		ReAuthURL: "https://cas.swjtu.edu.cn/authserver/reAuthLoginView.do",
		Username:  "2023000000",
		CreatedAt: time.Now().Add(-AppPendingTTL - time.Minute).Unix(),
	}
	if err := SaveAppPendingLogin(p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAppPendingLogin()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected expired pending to be ignored, got %+v", got)
	}
}

func TestAppPendingLoginRoundTrip(t *testing.T) {
	t.Setenv("SWJTU_CLI_CONFIG_DIR", t.TempDir())
	p := &AppPendingLogin{
		Cookies:    []HTTPCookie{{Name: "CASTGC", Value: "TGT-1", Domain: "cas.swjtu.edu.cn", Path: "/"}},
		ReAuthURL:  "https://cas.swjtu.edu.cn/authserver/reAuthLoginView.do",
		Username:   "2023000000",
		Service:    "https://cas.swjtu.edu.cn/authserver/mobile/callback?appId=1",
		ReAuthType: "3",
		CreatedAt:  time.Now().Unix(),
	}
	if err := SaveAppPendingLogin(p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAppPendingLogin()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ReAuthType != "3" || len(got.Cookies) != 1 {
		t.Fatalf("got %+v", got)
	}
	_ = ClearAppPendingLogin()
}
