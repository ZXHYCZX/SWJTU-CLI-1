package config

import (
	"testing"
	"time"
)

func TestAppLoginGuardWaits(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	g := &AppLoginGuard{
		LastPasswordAttempt: now.Add(-30 * time.Second).Unix(),
		LastSMSSent:         now.Add(-30 * time.Second).Unix(),
	}
	if got := g.PasswordWait(now); got <= 0 {
		t.Fatalf("password wait = %v, want > 0", got)
	}
	if got := g.SMSWait(now); got <= 0 {
		t.Fatalf("sms wait = %v, want > 0", got)
	}

	g.LastPasswordAttempt = now.Add(-AppPasswordCooldown - time.Second).Unix()
	g.LastSMSSent = now.Add(-AppSMSCooldown - time.Second).Unix()
	if got := g.PasswordWait(now); got != 0 {
		t.Fatalf("password wait = %v, want 0", got)
	}
	if got := g.SMSWait(now); got != 0 {
		t.Fatalf("sms wait = %v, want 0", got)
	}
}

func TestAppLoginGuardRoundTrip(t *testing.T) {
	t.Setenv("SWJTU_CLI_CONFIG_DIR", t.TempDir())
	g := &AppLoginGuard{LastPasswordAttempt: 123, LastSMSSent: 456}
	if err := SaveAppLoginGuard(g); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAppLoginGuard()
	if err != nil {
		t.Fatal(err)
	}
	if got.LastPasswordAttempt != 123 || got.LastSMSSent != 456 {
		t.Fatalf("got %+v", got)
	}
	if err := ClearAppLoginGuard(); err != nil {
		t.Fatal(err)
	}
	got, err = LoadAppLoginGuard()
	if err != nil {
		t.Fatal(err)
	}
	if got.LastPasswordAttempt != 0 || got.LastSMSSent != 0 {
		t.Fatalf("expected empty guard, got %+v", got)
	}
}
