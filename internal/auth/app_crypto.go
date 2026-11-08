package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// 扬华小智 App 内置的 RSA-1024 密钥对。公钥用于加密请求参数，
// 私钥用于解密服务端响应中的 d 字段。两者与 APK 内的硬编码值一致。
const appPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwcUzGAiqqFaskHfFZjsasgmd+03kdMxkTNu9rKvLyJAtXwmj6tvR6Ej2Mb/0iFiNd0L2/5QbTjSQWpogzKZ3+iBWRWMpOlGBb86VpEBm9PjwCXlMN8f6zch29NdpU9/vnyXUC5hWtY5sd5Yx8D1SE9hhoYX0+LTE951qoVWBP9wIDAQAB
-----END PUBLIC KEY-----`

const appPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMSjjIFAPHmGh5VJQWSCk3N6Q1hvqvvsK6BAQKuKg6G2SX652l2T9/UrBw2q7S9YMnJxVMoo0uJpYaZCZupJ8nP2xDTYhPieNZtzjbTU3Htvvw6aDl0we7yDNx5P7BZ3nozTArPoDwkZvuSWuoMxrVRbYIm76T01Jc70cemTZCwLAgMBAAECgYEAuqgM/bv+K9V56knJWyFf2mQafV4yzkRW/R1AxhUL8ntYtISzNdT5sK4RWfYAg8qSyHOv6t5poCYsXWf2zTs4exM+5Jwq1Hrn43oKASCg4mo1HRYJUudX0Cu381mGJsmRukbznEdB59ksyOnRg0z8yz/tvm0C/dpXK7oEf/IGIrECQQD5zSAdvdcNzBRm15peepR+XVtcPEpbi2NjUmP6u0x4+1JqP2sPGycS4fbssxm/UpCwiQNcS0aB7Mx5d6NYN5QfAkEAyYS05rJKI9imY/hNXRD6hrhoeUYXNR9DIJFePTfVMnYDG5jYOvDGjMxo92QWYrVk6QRSAotTtDbem7ucHoZKlQJAWVgUdI7BrB2h7maOv9v34HpjgsnNjpB8K7n8KGF1KJA7GeU01WJQx2AqgN5OBy/wsDNREGGcBjw7pfY0Zgj64QJBAIy6XzaoFXx5BKHVufkfLUU9rL/cQcK4RUGOIvivb/RgU4VHNOHcWVvkN/1j6Pof4QuVF8xtDhRRKR4qYzkx4Q0CQQDhu1LCZW2IgzFlwpwoXMXcf7fD0UAdZIU0e8uj5WcKrINDr59R8YmXk8HKRaQPg9qD07U7XkJnGI3W7340QwDY
-----END PRIVATE KEY-----`

type appKeySet struct {
	pub  *rsa.PublicKey
	priv *rsa.PrivateKey
}

var (
	appKeysOnce sync.Once
	appKeys     appKeySet
	appKeysErr  error
)

func loadAppKeys() (*appKeySet, error) {
	appKeysOnce.Do(func() {
		pubBlock, _ := pem.Decode([]byte(appPublicKeyPEM))
		if pubBlock == nil {
			appKeysErr = errors.New("App 公钥 PEM 解析失败")
			return
		}
		pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
		if err != nil {
			appKeysErr = fmt.Errorf("解析 App 公钥失败: %w", err)
			return
		}
		pub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			appKeysErr = errors.New("App 公钥不是 RSA 公钥")
			return
		}

		privBlock, _ := pem.Decode([]byte(appPrivateKeyPEM))
		if privBlock == nil {
			appKeysErr = errors.New("App 私钥 PEM 解析失败")
			return
		}
		privAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err != nil {
			appKeysErr = fmt.Errorf("解析 App 私钥失败: %w", err)
			return
		}
		priv, ok := privAny.(*rsa.PrivateKey)
		if !ok {
			appKeysErr = errors.New("App 私钥不是 RSA 私钥")
			return
		}
		appKeys = appKeySet{pub: pub, priv: priv}
	})
	if appKeysErr != nil {
		return nil, appKeysErr
	}
	return &appKeys, nil
}

// appEncrypt 复刻 package:encrypt 的分块 RSA/PKCS#1 v1.5：
// 每块明文最多 keyBytes-11 字节，逐块加密后拼接，再整体 base64。
func appEncrypt(plain []byte) (string, error) {
	keys, err := loadAppKeys()
	if err != nil {
		return "", err
	}
	k := keys.pub.Size()
	chunk := k - 11
	if chunk <= 0 {
		return "", errors.New("App RSA 密钥长度异常")
	}
	out := make([]byte, 0, ((len(plain)+chunk-1)/chunk)*k)
	for i := 0; i < len(plain); i += chunk {
		end := i + chunk
		if end > len(plain) {
			end = len(plain)
		}
		block, err := rsa.EncryptPKCS1v15(rand.Reader, keys.pub, plain[i:end])
		if err != nil {
			return "", fmt.Errorf("App RSA 加密失败: %w", err)
		}
		out = append(out, block...)
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

// appDecrypt 解密服务端响应 d 字段：base64 → 按密钥长度分块 → PKCS#1 v1.5。
func appDecrypt(encoded string) ([]byte, error) {
	keys, err := loadAppKeys()
	if err != nil {
		return nil, err
	}
	clean := strings.Join(strings.Fields(encoded), "")
	ct, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("App 响应 base64 解码失败: %w", err)
	}
	k := keys.priv.Size()
	if k <= 0 || len(ct) == 0 || len(ct)%k != 0 {
		return nil, fmt.Errorf("App 响应密文长度异常: %d", len(ct))
	}
	var out []byte
	for i := 0; i < len(ct); i += k {
		block, err := rsa.DecryptPKCS1v15(nil, keys.priv, ct[i:i+k])
		if err != nil {
			return nil, fmt.Errorf("App 响应解密失败: %w", err)
		}
		out = append(out, block...)
	}
	return out, nil
}
