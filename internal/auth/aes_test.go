package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
)

// decryptForTest 用已知 salt/iv 解密密文并去 PKCS7。
func decryptForTest(t *testing.T, cipherB64, salt, iv string) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		t.Fatalf("密文不是合法 base64: %v", err)
	}
	if len(data)%aes.BlockSize != 0 {
		t.Fatalf("密文长度 %d 不是块大小的整数倍", len(data))
	}
	block, err := aes.NewCipher([]byte(salt))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, []byte(iv)).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad <= 0 || pad > aes.BlockSize {
		t.Fatalf("PKCS7 padding 非法: %d", pad)
	}
	return string(out[:len(out)-pad])
}

func TestEncryptPasswordRoundTrip(t *testing.T) {
	const (
		salt     = "PqL66EZRnjdvRgYf" // 登录页样例盐
		iv       = "Abcdefgh23456789"
		password = "S3cret!密码"
	)
	cipherB64, err := encryptPasswordIV(password, salt, iv)
	if err != nil {
		t.Fatal(err)
	}
	plain := decryptForTest(t, cipherB64, salt, iv)
	if len(plain) < 64 || !strings.HasSuffix(plain, password) {
		t.Fatalf("解密结果不以原密码结尾: %q", plain)
	}
	for _, ch := range plain[:64] {
		if !strings.ContainsRune(aesChars, ch) {
			t.Fatalf("随机前缀字符 %q 不在 $aes_chars 中", ch)
		}
	}
}

func TestEncryptPasswordEmptySalt(t *testing.T) {
	got, err := EncryptPassword("abc", "")
	if err != nil || got != "abc" {
		t.Fatalf("salt 为空应原样返回: got=%q err=%v", got, err)
	}
}

func TestEncryptPasswordBadSaltLen(t *testing.T) {
	if _, err := EncryptPassword("abc", "shortsalt"); err == nil {
		t.Fatal("非 16 位盐应报错")
	}
}

func TestExtractLoginError(t *testing.T) {
	page := `<html><body><span id="msg" class="auth_error">验证码错误，请重新输入</span></body></html>`
	if got := extractLoginError([]byte(page)); got != "验证码错误，请重新输入" {
		t.Fatalf("got %q", got)
	}
	if got := extractLoginError([]byte(`<span id="showErrorTip">账号或密码错误</span>`)); got != "账号或密码错误" {
		t.Fatalf("got %q", got)
	}
	if got := extractLoginError([]byte(`<html>没有错误信息</html>`)); got != "" {
		t.Fatalf("无错误信息时应为空，got %q", got)
	}
}

func TestLoginPageFieldExtraction(t *testing.T) {
	page := []byte(`<input type="hidden" id="pwdEncryptSalt" value="PqL66EZRnjdvRgYf" />` +
		`<input type="hidden" name="lt" value="LT-123" />` +
		`<input type="hidden" name="execution" value="e1s1" />`)
	if got := firstGroup(reSalt, page); got != "PqL66EZRnjdvRgYf" {
		t.Fatalf("salt = %q", got)
	}
	if got := firstGroup(reExecution, page); got != "e1s1" {
		t.Fatalf("execution = %q", got)
	}
	if got := firstGroup(reLT, page); got != "LT-123" {
		t.Fatalf("lt = %q", got)
	}
}
