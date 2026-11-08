package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCredentialsRoundTrip(t *testing.T) {
	t.Setenv("SWJTU_CLI_CONFIG_DIR", t.TempDir())
	c := &Credentials{
		Username:  "2023111111",
		Password:  "pw",
		Token:     "tok-1",
		LoginTime: 1700000000,
		UserInfo:  []byte(`{"name":"张三"}`),
	}
	if err := SaveCredentials(c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Username != c.Username || got.Token != c.Token || got.LoginTime != c.LoginTime {
		t.Fatalf("round-trip 不一致: %+v", got)
	}
	// SaveCredentials 会重排缩进，按紧凑 JSON 比较
	var buf bytes.Buffer
	if err := json.Compact(&buf, got.UserInfo); err != nil {
		t.Fatal(err)
	}
	if buf.String() != `{"name":"张三"}` {
		t.Fatalf("UserInfo 不一致: %s", buf.String())
	}
}

func TestCredentialsExpired(t *testing.T) {
	c := &Credentials{Token: "t", LoginTime: 100}
	if !c.Expired(100 + TokenTTLSeconds) {
		t.Fatal("超过 TTL 应视为过期")
	}
	if c.Expired(100 + TokenTTLSeconds - 1) {
		t.Fatal("TTL 内不应过期")
	}
	c.Token = ""
	if !c.Expired(100) {
		t.Fatal("无 token 应视为过期")
	}
}

func TestClearCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SWJTU_CLI_CONFIG_DIR", dir)
	if err := SaveCredentials(&Credentials{Username: "u", Password: "p", Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := ClearCredentials(); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCredentials()
	if err != nil || c != nil {
		t.Fatalf("清除后应返回 nil: c=%v err=%v", c, err)
	}
	// 重复清除不报错
	if err := ClearCredentials(); err != nil {
		t.Fatalf("重复清除不应报错: %v", err)
	}
}

func TestLoadCredentialsMissingFile(t *testing.T) {
	t.Setenv("SWJTU_CLI_CONFIG_DIR", t.TempDir())
	c, err := LoadCredentials()
	if err != nil || c != nil {
		t.Fatalf("无凭据文件应返回 (nil, nil): c=%v err=%v", c, err)
	}
}
