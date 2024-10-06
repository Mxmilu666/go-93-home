package source

import (
	"anythingathome-golang/source/helper"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

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
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false
	}
	tokenString := parts[1]

	// 获取 JWTHelper 实例
	jwtHelper, err := helper.GetInstance()
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

	// 提取声明（claims）并进行额外的验证
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
func GetAvroBytes(files []helper.BMCLAPIObject) ([]byte, error) {
	data, err := helper.ComputeAvroBytes(files)
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

// toUrlSafeBase64String 将字节数组转换为 URL 安全的 Base64 字符串
func toUrlSafeBase64String(data []byte) string {
	// 使用标准的 Base64 编码
	s := base64.StdEncoding.EncodeToString(data)
	// 替换掉不安全的 URL 字符
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	// 去掉尾部的 =
	s = strings.TrimRight(s, "=")
	return s
}

// getSign 生成签名
func getSign(path string, secret string) (string, error) {
	timestamp := time.Now().UnixMilli() + 5*60*1000
	e := fmt.Sprintf("%v", strings.ToLower(fmt.Sprintf("%x", timestamp)))
	h := sha1.New()

	// 将 secret + path + e 进行哈希计算
	_, err := h.Write([]byte(secret + path + e))
	if err != nil {
		return "", err
	}
	signBytes := h.Sum(nil)

	// 将哈希值转换为 URL 安全的 Base64 字符串
	sign := toUrlSafeBase64String(signBytes)

	// 返回签名字符串
	return fmt.Sprintf("s=%s&e=%s", sign, e), nil
}

// 随机获取节点文件并检查hash
func CheckFileHash(database *mongo.Client, oid bson.ObjectID) error {
	//获取随机文件
	file, err := GetRandomFile(database, DatabaseName, FilesCollection)
	if err != nil {
		return fmt.Errorf("error getting random file: %v", err)
	}

	cluster, err := GetClusterById(database, DatabaseName, ClusterCollection, oid)
	if err != nil {
		return fmt.Errorf("error getting cluster: %v", err)
	}

	signature, err := getSign(file.Hash, cluster.ClusterSecret)
	if err != nil {
		return fmt.Errorf("error generating signature: %v", err)
	}

	// 构建 URL，请求检查文件的 hash
	url := fmt.Sprintf("%s/download/%s?%s", cluster.EndPoint, file.Hash, signature)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 30 * time.Second,
				Resolver: &net.Resolver{
					PreferGo: false,
					Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return net.Dial("udp", "2606:4700:4700::1111:53")
					},
				},
			}).DialContext,
		},
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	// 设个 ua，别把主控当机器人拦了
	req.Header.Set("User-Agent", "Anything@Home-ctrl")

	req.Close = true

	// 发起请求
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to check hash, status code: %d", resp.StatusCode)
	}

	// 读取响应体中的文件内容
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// 计算响应内容的 SHA1 hash
	downloadedHash := sha1.Sum(body)
	downloadedHashString := fmt.Sprintf("%x", downloadedHash)

	// 将下载的文件 hash 与数据库中的 hash 比较
	if downloadedHashString != file.Hash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", file.Hash, downloadedHashString)
	}

	// 给巡检流量也放到数据库里
	err = RecordTrafficToNode(database, DatabaseName, TrafficCollection, cluster.ClusterID, file.Size, int64(1))
	if err != nil {
		return fmt.Errorf("Error recording traffic and request data sent to node:", err)
	}

	return nil
}

// 删除节点在线
func removeClusterByID(clusterID bson.ObjectID) {
	for i, cluster := range onlineClusters {
		if cluster.ClusterID == clusterID {
			// 删除节点
			onlineClusters = append(onlineClusters[:i], onlineClusters[i+1:]...)
			break
		}
	}
}
