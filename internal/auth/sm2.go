package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

// yhxtSM2PublicKey 是扬华学堂前端（/h5/static/js/index.*.js 模块 7d8a）
// 内置的 SM2 公钥（04 开头的非压缩点，0491 21...79eab）。
// 所有需认证接口的请求参数以 {_t: 毫秒时间戳, _d: 参数对象} 包装后
// 用此公钥 SM2 加密（C1C3C2 顺序），hex 编码后放入 _j 参数/字段。
const yhxtSM2PublicKey = "049121366953ab694e775b71062461b91b1648316ae32d89ad1b59bc6a4b0a5c6184c9851df7e97b6a4948618c1e7a30d740dca436f0556cadce9bc4d67a179eab"

// SM2EncryptHex 用扬华学堂公钥做 SM2 加密，输出 hex(C1||C3||C2)。
func SM2EncryptHex(plain []byte) (string, error) {
	keyBytes, err := hex.DecodeString(yhxtSM2PublicKey)
	if err != nil {
		return "", fmt.Errorf("内置公钥非法: %w", err)
	}
	if len(keyBytes) != 65 || keyBytes[0] != 0x04 {
		return "", fmt.Errorf("内置公钥不是 65 字节非压缩点")
	}
	pub := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     new(big.Int).SetBytes(keyBytes[1:33]),
		Y:     new(big.Int).SetBytes(keyBytes[33:65]),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return "", fmt.Errorf("内置公钥不在 SM2 曲线上")
	}
	ct, err := sm2.Encrypt(pub, plain, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return "", fmt.Errorf("SM2 加密失败: %w", err)
	}
	return hex.EncodeToString(ct), nil
}
