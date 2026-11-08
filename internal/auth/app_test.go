package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// mustResponseEncrypt 用响应私钥对应的公钥加密，模拟服务端返回的 d。
func mustResponseEncrypt(t *testing.T, s string) string {
	t.Helper()
	keys, err := loadAppKeys()
	if err != nil {
		t.Fatal(err)
	}
	pub := &keys.priv.PublicKey
	block := pub.Size()
	chunk := block - 11
	var ct []byte
	plain := []byte(s)
	for i := 0; i < len(plain); i += chunk {
		end := i + chunk
		if end > len(plain) {
			end = len(plain)
		}
		out, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plain[i:end])
		if err != nil {
			t.Fatal(err)
		}
		ct = append(ct, out...)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

func TestParseAppEnvelopeDecryptsStringData(t *testing.T) {
	enc := mustResponseEncrypt(t, `{"accessToken":"token","user":{"userId":"1"}}`)
	body, _ := json.Marshal(map[string]any{"e": 0, "m": "操作成功", "d": enc})
	got, err := parseAppEnvelope(200, body)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatal(err)
	}
	if v.AccessToken != "token" {
		t.Fatalf("accessToken = %q", v.AccessToken)
	}
}

func TestParseAppEnvelopePlainObjectData(t *testing.T) {
	body := []byte(`{"e":0,"m":"ok","d":{"week":7}}`)
	got, err := parseAppEnvelope(200, body)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Week int `json:"week"`
	}
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatal(err)
	}
	if v.Week != 7 {
		t.Fatalf("week = %d", v.Week)
	}
}

func TestParseAppEnvelopeSessionExpired(t *testing.T) {
	for _, code := range []int{10013, 4600400} {
		body, _ := json.Marshal(map[string]any{"e": code, "m": "登录已失效"})
		_, err := parseAppEnvelope(200, body)
		var unauth *UnauthenticatedError
		if !errors.As(err, &unauth) {
			t.Fatalf("code %d: got %v, want UnauthenticatedError", code, err)
		}
	}
}

func TestParseAppEnvelopeServiceError(t *testing.T) {
	body := []byte(`{"e":500,"m":"服务器开小差"}`)
	_, err := parseAppEnvelope(200, body)
	var svc *ServiceError
	if !errors.As(err, &svc) {
		t.Fatalf("got %v, want ServiceError", err)
	}
	if svc.Msg != "服务器开小差" {
		t.Fatalf("msg = %q", svc.Msg)
	}
}

func TestParseAppEnvelopeStringErrorCode(t *testing.T) {
	body := []byte(`{"e":"10013","m":"expired"}`)
	_, err := parseAppEnvelope(200, body)
	var unauth *UnauthenticatedError
	if !errors.As(err, &unauth) {
		t.Fatalf("got %v, want UnauthenticatedError", err)
	}
}
