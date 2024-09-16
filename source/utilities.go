package source

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"open93athome-golang/source/Helper"
	"strings"

	"github.com/klauspost/compress/zstd"
	
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type File struct {
    Path  string `avro:"path"`
    Hash  string `avro:"hash"`
    Size  int64  `avro:"size"`
    Mtime int64  `avro:"mtime"`
}

// computeSignature 计算并验证签名
func computeSignature(challenge, signature, secret string) bool {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(challenge))
	expectedSignature := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// verifyClusterRequest 验证请求
func verifyClusterRequest(c *gin.Context) bool {
	// 从请求头中获取 Authorization 字段
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return false
	}

	// 按空格分割，获取令牌部分
	// 格式通常为 "Bearer token_value"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false
	}
	tokenString := parts[1]

	// 获取 JWTHelper 实例
	jwtHelper, err := Helper.GetInstance()
	if err != nil {
		return false
	}

	// 验证令牌，受众为 'cluster'
	token, err := jwtHelper.VerifyToken(tokenString, "cluster")
	if err != nil {
		return false
	}

	// 检查令牌是否有效
	if !token.Valid {
		return false
	}

	// 可选：提取声明（claims）并进行额外的验证
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}

	// 检查特定的声明，如 clusterId
	if _, exists := claims["data"].(map[string]interface{})["clusterId"]; !exists {
		return false
	}

	return true
}

// 获取 avro
func GetAvroBytes(files []Helper.BMCLAPIObject) ([]byte, error) {
	data, err := Helper.ComputeAvroBytes(files)
	if err != nil {
        return nil, err
    }

    // 使用 zstd 压缩 Avro 数据
    encoder, err := zstd.NewWriter(nil)
    if err != nil {
        return nil, err
    }
    compressedData := encoder.EncodeAll(data, nil)

    return compressedData, nil
}



