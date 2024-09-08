package source

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// computeSignature 计算并验证签名
func computeSignature(challenge, signature, secret string) bool {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(challenge))
	expectedSignature := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}
