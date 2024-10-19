package source

import (
	"anythingathome-golang/source/helper"
	"anythingathome-golang/source/helper/dns"
	"anythingathome-golang/source/logger"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zishang520/socket.io/v2/socket"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var (
	r                   *gin.Engine // 将 gin 的路由器也设为全局变量
	onlineClusters      []Clusters
	sessionToClusterMap = make(map[string]bson.ObjectID)
)

type Clusters struct {
	ClusterID bson.ObjectID `bson:"_id" json:"clusterId"`
	Endpoint  string        `bson:"endpoint" json:"endpoint"`
}

// corsMiddleware 添加 CORS 头部
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func filterLogs() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// 获取完整请求的 URL
		fullURL, err := url.QueryUnescape(c.Request.URL.String())
		if err != nil {
			logger.Error("Error decoding URL:", err)
			return
		}

		fullURL = strings.ReplaceAll(fullURL, "%", "%%")

		c.Next()

		latency := time.Since(start)

		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		userAgent := c.Request.UserAgent()

		// 构造日志输出格式
		logger.Info(fmt.Sprintf(
			"%3d | %13v | %15s | %-7s | %s | %s\n",
			statusCode, // 状态码
			latency,    // 延迟时间
			clientIP,   // 客户端IP
			method,     // 请求方法
			userAgent,  // 用户代理
			fullURL,    // 完整的 URL 包括路径和查询参数
		))
	}
}

func SetupServer(ip string, port string, database *mongo.Client, cfConfig *helper.CloudflareConfig, Config *Config) {
	gin.SetMode(gin.ReleaseMode)

	server := socket.NewServer(nil, nil)

	server.On("connection", func(clients ...any) {
		client := clients[0].(*socket.Socket)

		auth := client.Handshake().Auth

		token, ok := auth.(map[string]interface{})
		if !ok {
			logger.Info("Invalid token type")
			client.Disconnect(true)
		}

		tokenStr, ok := token["token"].(string)
		if !ok || tokenStr == "" {
			logger.Info("Invalid or missing token format")
			client.Disconnect(true)
		}

		// 获取 JWT helper 实例
		jwtHelper, err := helper.GetInstance()
		if err != nil {
			logger.Error("Error initializing JWT helper")
			client.Disconnect(true)
		}

		if len(strings.Split(tokenStr, ".")) != 3 {
			logger.Error("Malformed JWT token")
			client.Disconnect(true)
		}

		// 验证 token
		claims, err := jwtHelper.VerifyToken(tokenStr, "cluster")
		if err != nil {
			logger.Error("Token verification failed:", err)
			client.Disconnect(true)
		}

		id, ok := claims.Claims.(jwt.MapClaims)
		if !ok || !claims.Valid {
			logger.Error("Invalid jwt")
			client.Disconnect(true)
		}

		oid, err := bson.ObjectIDFromHex(id["data"].(map[string]interface{})["clusterId"].(string))
		if err != nil {
			logger.Error("Invalid clusterId: %v", err)
			client.Disconnect(true)
		}

		sessionToClusterMap[string(client.Id())] = oid

		client.On("event", func(datas ...any) {
			logger.Info("%v", datas...)
		})

		// enable 部分
		client.On("enable", func(datas ...any) {
			logger.Info("cluster %v requests enable", oid)
			for _, data := range datas {
				if m, ok := data.(map[string]interface{}); ok {
					var endpoint string
					var host string
					var port float64
					if h, exists := m["host"]; exists {
						host = h.(string)
						if p, exists := m["port"]; exists {
							port = p.(float64)
							endpoint = fmt.Sprintf("https://%v:%v", host, port)
						} else {
							ack := datas[len(datas)-1].(func([]any, error))
							ack([]any{[]any{map[string]string{"message": "Port not found"}}}, nil)
							client.Disconnect(true)
						}
					} else {
						// 处理没有host的情况
						host = client.Handshake().Address
						colonIndex := strings.LastIndex(host, ":")
						host = host[:colonIndex]
						if p, exists := m["port"]; exists {
							port = p.(float64)
							endpoint = fmt.Sprintf("https://%v:%v", host, port)
						} else {
							ack := datas[len(datas)-1].(func([]any, error))
							ack([]any{[]any{map[string]string{"message": "Port not found"}}}, nil)
							client.Disconnect(true)
						}
					}

					var byoc bool
					if m["byoc"] == nil {
						byoc = false
					} else {
						byoc, _ = m["byoc"].(bool)
					}

					if !byoc {
						host = strings.Trim(host, "[]")
						var record dns.DNSRecord
						if net.ParseIP(host).To4() != nil {
							// IPv4
							record = dns.DNSRecord{
								Type:    "A",
								Name:    oid.Hex() + "." + cfConfig.Domain,
								Content: host,
								TTL:     60,
								Proxied: false,
							}
						} else {
							// IPv6
							record = dns.DNSRecord{
								Type:    "AAAA",
								Name:    oid.Hex() + "." + cfConfig.Domain,
								Content: host,
								TTL:     60,
								Proxied: false,
							}
						}
						zoneID, err := dns.GetZoneID(cfConfig.AuthEmail, cfConfig.AuthKey, cfConfig.Domain)
						if err != nil {
							logger.Info("Error getting zone ID: %v", err)
							return
						}

						if err := dns.AddDNSRecord(cfConfig.AuthEmail, cfConfig.AuthKey, zoneID, record); err != nil {
							logger.Error("Error adding DNS record: %v", err)
						} else {
							logger.Info("DNS record added successfully.")
						}

						endpoint = fmt.Sprintf("https://%v:%v", oid.Hex()+"."+cfConfig.Domain, port)

						time.Sleep(10000 * time.Millisecond)
					}

					if endpoint != "" {
						setcluster := bson.M{
							"endPoint": endpoint,
							"flavor":   m["flavor"],
							"byoc":     m["byoc"],
						}

						err = UpdateClusterFieldsById(database, DatabaseName, ClusterCollection, oid, setcluster)
						if err != nil {
							logger.Error("%v", err)
						}

						// 尝试巡检五次
						success := true
						for i := 0; i < 5; i++ {
							err := CheckFileHash(database, oid)
							if err != nil {
								logger.Error("cluster %v enable failed: %v", oid, err)
								ack := datas[len(datas)-1].(func([]any, error))
								ack([]any{[]any{map[string]string{"message": fmt.Sprintf("服务器查活失败，请检查端口是否可用(%v)：Error：%v", endpoint, err)}}}, nil)
								success = false
								break
							}
							time.Sleep(200 * time.Millisecond)
						}

						if success {
							ack := datas[len(datas)-1].(func([]any, error))
							ack([]any{[]any{nil, true}}, nil)
							var newCluster = Clusters{
								ClusterID: oid,
								Endpoint:  endpoint,
							}
							setcluster := bson.M{
								"isEnable": true,
							}
							err = UpdateClusterFieldsById(database, DatabaseName, ClusterCollection, oid, setcluster)
							if err != nil {
								logger.Error("%v", err)
							}
							onlineClusters = append(onlineClusters, newCluster)
							logger.Info("cluster %v successfully enabled", oid)
						}
					}
				}
			}
		})

		// keepalive 部分
		client.On("keep-alive", func(datas ...any) {
			session := string(client.Id())
			ack := datas[len(datas)-1].(func([]any, error))
			clusterID, exists := sessionToClusterMap[session]
			if exists {
				for _, data := range datas {
					if m, ok := data.(map[string]interface{}); ok {
						bytesVal := int64(m["bytes"].(float64))
						hitsVal := int64(m["hits"].(float64))
						// 记录流量和请求数
						err = RecordTrafficFromNode(database, DatabaseName, TrafficCollection, clusterID, bytesVal, hitsVal)
						if err != nil {
							logger.Error("Error recording traffic and request data sent to node:", err)
							return
						}
						logger.Info("cluster %v keepalive successfully: %v", clusterID, m)
						ack([]any{[]any{nil, time.Now().Format(time.RFC3339)}}, nil)
					}
				}
			} else {
				ack := datas[len(datas)-1].(func([]any, error))
				ack([]any{[]any{map[string]string{"message": "Forbidden"}}}, nil)
				client.Disconnect(true)
			}
		})

		// request-cert 部分
		client.On("request-cert", func(datas ...any) {
			session := string(client.Id())
			ack := datas[len(datas)-1].(func([]any, error))
			clusterID, exists := sessionToClusterMap[session]
			if exists {
				cert, valid, err := GetCertOrRequest(database, DatabaseName, CertCollection, oid)
				if err != nil {
					logger.Error("%v", err)
				}

				if valid {
					ack([]any{[]any{nil, map[string]string{"_id": cert.Id.Hex(), "clusterId": oid.Hex(), "cert": cert.ClusterCert, "key": cert.ClusterKey, "expires": cert.ClusterExpiry.Format("2006-01-02 15:04:05 +0000 UTC"), "__v": "0"}}}, nil)
				} else {
					certStatus := helper.NewCertRequestStatus(cfConfig, database)
					myUser := helper.MyUser{
						Email: cfConfig.AuthEmail,
					}
					certChan := certStatus.RequestCert(clusterID.Hex(), &myUser)
					certificates := <-certChan // 等待证书或错误
					if certificates != nil {
						expiry, err := helper.GetCertificateExpiry(certificates.Certificate)
						if err != nil {
							logger.Error("Failed to get certificate expiry: %v", err)
						}
						setcluster := bson.M{
							"cluster_cert":   certificates.Certificate,
							"cluster_key":    certificates.PrivateKey,
							"cluster_expiry": expiry,
						}
						err = UpdateCertFieldsById(database, DatabaseName, CertCollection, oid, setcluster)
						if err != nil {
							logger.Error("%v", err)
						}

						ack([]any{[]any{nil, map[string]string{"_id": cert.Id.Hex(), "clusterId": oid.Hex(), "cert": string(certificates.Certificate), "key": string(certificates.PrivateKey), "expires": expiry.Format("2006-01-02 15:04:05 +0000 UTC"), "__v": "0"}}}, nil)
					} else {

					}
				}
				logger.Info("Found ClusterID: %s for session: %s\n", clusterID.Hex(), session)
				//ack([]any{[]any{nil, true}}, nil)
			} else {
				ack := datas[len(datas)-1].(func([]any, error))
				ack([]any{[]any{map[string]string{"message": "Forbidden"}}}, nil)
				client.Disconnect(true)
			}
		})

		// disable 部分
		client.On("disable", func(datas ...any) {
			session := string(client.Id())
			clusterID, exists := sessionToClusterMap[session]
			if exists {
				delete(sessionToClusterMap, string(client.Id()))
				setcluster := bson.M{
					"isEnable": false,
				}
				err = UpdateClusterFieldsById(database, DatabaseName, ClusterCollection, oid, setcluster)
				if err != nil {
					logger.Error("%v", err)
				}
				removeClusterByID(clusterID)
				logger.Info("Found ClusterID: %s for session: %s\n", clusterID.Hex(), session)
				ack := datas[len(datas)-1].(func([]any, error))
				ack([]any{[]any{nil, true}}, nil)
			} else {
				ack := datas[len(datas)-1].(func([]any, error))
				ack([]any{[]any{map[string]string{"message": "Forbidden"}}}, nil)
				client.Disconnect(true)
			}
		})

		client.On("disconnect", func(...any) {
		})
	})

	// 创建路由
	r = gin.New()

	// 添加 CORS 中间件
	r.Use(corsMiddleware())

	// 添加日志过滤中间件
	r.Use(filterLogs())

	// 根路由
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": "anythingathome-golang",
		})
	})
	openbmclapiAgent := r.Group("/openbmclapi-agent")
	{
		// challenge 路由
		openbmclapiAgent.GET("/challenge", func(c *gin.Context) {
			clusterId := c.Query("clusterId")
			if clusterId == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "clusterId is required"})
				return
			}

			// 将 clusterId 转换为 ObjectID
			oid, err := bson.ObjectIDFromHex(clusterId)
			if err != nil {
				logger.Error("Invalid clusterId: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid clusterId"})
				return
			}

			// 从数据库中获取指定的 Cluster
			cluster, err := GetClusterById(database, DatabaseName, ClusterCollection, oid)
			if err != nil {
				logger.Error("Error getting cluster: %v", err)
				c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
				return
			}

			if cluster.IsBanned {
				c.JSON(http.StatusForbidden, gin.H{"error": "Cluster is banned"})
				return
			}

			jwtHelper, err := helper.GetInstance()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error initializing JWT helper"})
				return
			}

			token, err := jwtHelper.IssueToken(map[string]interface{}{
				"clusterId": clusterId,
			}, "cluster-challenge", 60*5)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error issuing token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"challenge": token,
			})
		})

		// token 路由
		openbmclapiAgent.POST("/token", func(c *gin.Context) {
			var req struct {
				ClusterId string `json:"clusterId"`
				Signature string `json:"signature"`
				Challenge string `json:"challenge"`
			}
			//我讨厌 form
			contentType := c.Request.Header.Get("Content-Type")
			if strings.HasPrefix(contentType, "application/json") {
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON request body"})
					return
				}
			} else if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
				if err := c.Request.ParseForm(); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form data"})
					return
				}
				req.ClusterId = c.PostForm("clusterId")
				req.Signature = c.PostForm("signature")
				req.Challenge = c.PostForm("challenge")
			} else if strings.HasPrefix(contentType, "multipart/form-data") {
				if err := c.Request.ParseForm(); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form data"})
					return
				}
				req.ClusterId = c.PostForm("clusterId")
				req.Signature = c.PostForm("signature")
				req.Challenge = c.PostForm("challenge")
			} else {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "Unsupported Content-Type"})
				return
			}

			jwtHelper, err := helper.GetInstance()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error initializing JWT helper"})
				return
			}

			token, err := jwtHelper.VerifyToken(req.Challenge, "cluster-challenge")
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Invalid challenge token"})
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || !token.Valid {
				c.JSON(http.StatusForbidden, gin.H{"error": "Invalid challenge token"})
				return
			}

			clusterIdFromToken, ok := claims["data"].(map[string]interface{})["clusterId"].(string)
			if !ok || clusterIdFromToken != req.ClusterId {
				c.JSON(http.StatusForbidden, gin.H{"error": "Cluster ID mismatch"})
				return
			}

			// 将 clusterId 转换为 ObjectID
			oid, err := bson.ObjectIDFromHex(req.ClusterId)
			if err != nil {
				logger.Error("Invalid clusterId: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid clusterId"})
				return
			}

			// 从数据库中获取指定的 Cluster
			cluster, err := GetClusterById(database, DatabaseName, ClusterCollection, oid)
			if err != nil {
				logger.Error("Error getting cluster: %v", err)
				c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
				return
			}

			if !computeSignature(req.Challenge, req.Signature, cluster.ClusterSecret) {
				c.JSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
				return
			}

			newToken, err := jwtHelper.IssueToken(map[string]interface{}{
				"clusterId": req.ClusterId,
			}, "cluster", 60*60*24)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error issuing token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"token": newToken,
				"ttl":   1000 * 60 * 60 * 24, // 24小时
			})
		})
	}

	openbmclapi := r.Group("/openbmclapi")
	{
		// configuration 路由
		openbmclapi.GET("/configuration", func(c *gin.Context) {
			if !verifyClusterRequest(c) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			response := gin.H{
				"sync": gin.H{
					"concurrency": 10,
					"source":      "center",
				},
			}
			c.JSON(http.StatusOK, response)
		})

		// files 路由
		openbmclapi.GET("/files", func(c *gin.Context) {

			// 获取查询参数中的 lastModified
			lastModifiedStr := c.Query("lastModified")
			var lastModified int64 = 0
			if lastModifiedStr != "" {
				var err error
				lastModified, err = strconv.ParseInt(lastModifiedStr, 10, 64)
				if err != nil {
					logger.Error("Invalid lastModified parameter: %v", err)
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid lastModified parameter"})
					return
				}
			}

			// 获取 filelist
			filesInfo, err := GetDocuments[FileInfo](database, DatabaseName, FilesCollection, bson.M{}, lastModified)
			if err != nil {
				logger.Error("Error getting files: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get files"})
				return
			}

			// 如果没有文件，返回 204 状态码
			if len(filesInfo) == 0 {
				c.Status(http.StatusNoContent)
				return
			}

			// 将 filesInfo 转换为 BMCLAPIObject
			var helperFiles []helper.BMCLAPIObject
			for _, info := range filesInfo {
				helperFiles = append(helperFiles, helper.BMCLAPIObject{
					Path:         "/files/" + info.SyncSource + "/" + strings.Replace(info.FileName, "\\", "/", -1),
					Hash:         info.Hash,
					Size:         info.Size,
					LastModified: info.MTime.Time().UnixMilli(),
				})
			}

			avroData, err := GetAvroBytes(helperFiles)
			if err != nil {
				logger.Error("Error generating Avro data: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate Avro data"})
				return
			}

			// 在这里处理已授权的请求
			c.Header("Content-Type", "application/octet-stream")
			c.Header("Content-Disposition", "attachment; filename=\"filelist\"")
			c.Data(http.StatusOK, "application/octet-stream", avroData)
		})

	}

	// API 路由
	api := r.Group("/api")
	{
		// rank 路由
		api.GET("/rank", func(c *gin.Context) {
			clusters, err := GetClusterTrafficDetails(database, DatabaseName, ClusterCollection, TrafficCollection)
			if err != nil {
				log.Fatal(err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": err.Error(),
				})
			}
			c.JSON(http.StatusOK, clusters)
		})

		// login 路由
		api.GET("/login/github", func(c *gin.Context) {
			config := getGitHubOAuthConfig(c, Config.GitHubOAuth.ClientID, Config.GitHubOAuth.ClientID)
			loginWithOAuth(c, config)
		})

	}
	// 下载文件
	r.GET("/files/*filepath", func(c *gin.Context) {
		// 获取整个路径
		fullPath := c.Param("filepath")

		// 拆分路径
		pathSegments := strings.Split(strings.Trim(fullPath, "/"), "/")
		if len(pathSegments) < 2 {
			c.String(http.StatusBadRequest, "Invalid path")
			return
		}

		// 获取 syncSource 和 fileName
		syncSource := pathSegments[0]
		fileName := strings.Join(pathSegments[1:], "/")

		// 从数据库查询文档
		fileRecord, err := GetFileFromDB(database, DatabaseName, FilesCollection, syncSource, fileName)
		if err != nil {
			c.String(http.StatusNotFound, "404 not found")
			return
		}

		// 检查 onlineClusters 是否为空
		if len(onlineClusters) > 0 {
			// 从在线集群中随机选择一个 clusterId
			rand.Seed(time.Now().UnixNano())
			cluster := onlineClusters[rand.Intn(len(onlineClusters))]

			// 从节点中获取文件
			clusterfile, err := GetClusterById(database, DatabaseName, ClusterCollection, cluster.ClusterID)
			if err != nil {
				c.String(http.StatusNotFound, "404 not found on cluster")
				return
			}

			signature, err := getSign(fileRecord.Hash, clusterfile.ClusterSecret)
			if err != nil {
				c.String(http.StatusInternalServerError, "error generating signature: %v", err)
				return
			}

			url := fmt.Sprintf("%s/download/%s?%s", clusterfile.EndPoint, fileRecord.Hash, signature)

			// 记录给节点的流量和请求数
			err = RecordTrafficToNode(database, DatabaseName, TrafficCollection, cluster.ClusterID, fileRecord.Size, int64(1))
			if err != nil {
				logger.Error("Error recording traffic and request data sent to node:", err)
			}

			c.Redirect(http.StatusFound, url)
			return
		}

		// 从数据库的 localDir 字段中获取文件路径
		filePath := fileRecord.LocalDir

		// 打开文件
		file, err := os.Open(filePath)
		if err != nil {
			logger.Error("Error open files: %v", err)
		}
		defer file.Close()

		// 读取文件内容
		fileContent, err := io.ReadAll(file)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error reading file")
			return
		}

		// 获取文件后缀名并根据扩展名设置Content-Type
		ext := filepath.Ext(filePath)
		mimeType := mime.TypeByExtension(ext)
		if mimeType == "" {
			// 如果无法自动识别类型，使用通用的二进制流类型
			mimeType = "application/octet-stream"
		}

		// 设置 Content-Type 并将文件内容作为响应返回
		c.Data(http.StatusOK, mimeType, fileContent)
	})

	// 使用 socketio 处理 WebSocket 请求
	r.GET("/socket.io/*any", gin.WrapH(server.ServeHandler(nil)))
	r.POST("/socket.io/*any", gin.WrapH(server.ServeHandler(nil)))

	logger.Info("Server is running at %s:%s", ip, port)
	// 启动 HTTP 服务器
	if err := r.Run(ip + ":" + port); err != nil {
		logger.Fatal("Server failed to run: %v", err)
	}
}
