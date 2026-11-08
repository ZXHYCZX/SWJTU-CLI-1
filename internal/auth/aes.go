package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

// aesChars 与 SWJTU 统一认证登录页 encrypt.js 中的 $aes_chars 一致
//（去除了易混淆字符 I/L/O/U/V/g/l/o/q/u/v/0/1/9）。
const aesChars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

func randomString(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(aesChars)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = aesChars[idx.Int64()]
	}
	return string(out), nil
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	return append(b, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// EncryptPassword 复刻统一认证 encrypt.js 的 encryptAES：
// 明文 = randomString(64) + 密码，key = 登录页下发的 pwdEncryptSalt（16 字节 → AES-128），
// iv = randomString(16)，CBC + PKCS7，输出 base64。salt 为空时原样返回密码。
func EncryptPassword(password, salt string) (string, error) {
	iv, err := randomString(16)
	if err != nil {
		return "", fmt.Errorf("生成随机 IV 失败: %w", err)
	}
	return encryptPasswordIV(password, salt, iv)
}

// encryptPasswordIV 是 EncryptPassword 的可测试内核（固定 IV）。
func encryptPasswordIV(password, salt, iv string) (string, error) {
	if salt == "" {
		return password, nil
	}
	if len(salt) != 16 {
		return "", &LoginError{Msg: fmt.Sprintf("登录页下发的加密盐长度异常（%d，应为 16）", len(salt))}
	}
	prefix, err := randomString(64)
	if err != nil {
		return "", fmt.Errorf("生成随机前缀失败: %w", err)
	}
	block, err := aes.NewCipher([]byte(salt))
	if err != nil {
		return "", fmt.Errorf("初始化 AES 失败: %w", err)
	}
	plain := pkcs7Pad([]byte(prefix+password), aes.BlockSize)
	enc := cipher.NewCBCEncrypter(block, []byte(iv))
	out := make([]byte, len(plain))
	enc.CryptBlocks(out, plain)
	return base64.StdEncoding.EncodeToString(out), nil
}
