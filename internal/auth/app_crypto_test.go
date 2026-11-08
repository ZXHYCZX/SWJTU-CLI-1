package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
)

func TestAppEncryptChunking(t *testing.T) {
	keys, err := loadAppKeys()
	if err != nil {
		t.Fatal(err)
	}
	block := keys.pub.Size()
	chunk := block - 11
	for _, n := range []int{1, chunk - 1, chunk, chunk + 1, 300} {
		plain := bytes.Repeat([]byte("A"), n)
		enc, err := appEncrypt(plain)
		if err != nil {
			t.Fatalf("encrypt %d: %v", n, err)
		}
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			t.Fatalf("base64 %d: %v", n, err)
		}
		wantBlocks := (n + chunk - 1) / chunk
		if len(raw) != wantBlocks*block {
			t.Fatalf("ciphertext length for %d = %d, want %d", n, len(raw), wantBlocks*block)
		}
	}
}

// 请求加密公钥与响应解密私钥不是同一对密钥：
// 公钥用于 content/authorization-str，私钥用于 d 字段。这里用私钥的
// 公钥部分构造响应密文，验证分块解密。
func TestAppDecryptChunking(t *testing.T) {
	keys, err := loadAppKeys()
	if err != nil {
		t.Fatal(err)
	}
	pub := &keys.priv.PublicKey
	block := pub.Size()
	chunk := block - 11
	for _, n := range []int{1, chunk, chunk + 1, 300} {
		plain := bytes.Repeat([]byte("B"), n)
		var ct []byte
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
		got, err := appDecrypt(base64.StdEncoding.EncodeToString(ct))
		if err != nil {
			t.Fatalf("decrypt %d: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round trip mismatch for %d bytes", n)
		}
	}
}

func TestAppDecryptRejectsBadInput(t *testing.T) {
	if _, err := appDecrypt("not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if _, err := appDecrypt(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected error for wrong ciphertext length")
	}
}
