package source

import (
	"fmt"
	"net/http"
	"time"

	"open93athome-golang/source/Helper"
	"open93athome-golang/source/logger"

	"github.com/gin-gonic/gin"
	socketio "github.com/googollee/go-socket.io"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var (
	server   *socketio.Server // 将 server 设为全局变量
	r        *gin.Engine      // 将 gin 的路由器也设为全局变量
	clusters []Cluster
)

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
		fullURL := c.Request.URL.String()

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

func SetupServer(ip string, port string, database *mongo.Client) {
	gin.SetMode(gin.ReleaseMode)

	// 创建新的 Socket.IO 服务器
	server = socketio.NewServer(nil)

	// 定义 Socket.IO 事件
	server.OnConnect("/", func(s socketio.Conn) error {
		logger.Info("Connected: %s", s.ID())
		s.SetContext("")
		return nil
	})

	server.OnEvent("/", "message", func(s socketio.Conn, msg string) {
		logger.Info("Received message: %s", msg)
		s.Emit("reply", "Received: "+msg)
	})

	server.OnError("/", func(s socketio.Conn, e error) {
		logger.Error("Socket.IO error: %v", e)
	})

	server.OnDisconnect("/", func(s socketio.Conn, reason string) {
		logger.Info("Disconnected: %s", reason)
	})

	// 创建路由
	r = gin.New()

	// 添加 CORS 中间件
	r.Use(corsMiddleware())

	// 添加日志过滤中间件
	r.Use(filterLogs())

	// 创建各种路由
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "HelloWorld",
		})
	})

	r.GET("/openbmclapi-agent/challenge", func(c *gin.Context) {
		var err error
		clusters, err = GetClusters(database, "93athome", "cluster")
		if err != nil {
			logger.Error("Error getting clusters: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting clusters"})
			return
		}

		clusterId := c.Query("clusterId")
		if clusterId == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "clusterId is required"})
			return
		}

		cluster, found := findClusterById(clusterId)
		if !found {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
			return
		}

		if cluster.isBanned {
			c.JSON(http.StatusForbidden, gin.H{"error": "Cluster is banned"})
			return
		}

		jwtHelper, err := Helper.GetInstance()
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

	// 使用 Gin 处理 WebSocket 请求
	r.GET("/socket.io/*any", gin.WrapH(server))
	r.POST("/socket.io/*any", gin.WrapH(server))

	// 启动 Socket.IO 服务器
	go func() {
		if err := server.Serve(); err != nil {
			logger.Fatal("Socket.IO server failed to start: %v", err)
		}
	}()
	defer server.Close() // 在退出时关闭 Socket.IO 服务器

	logger.Info("Server is running at %s:%s", ip, port)
	// 启动 HTTP 服务器
	if err := r.Run(ip + ":" + port); err != nil {
		logger.Fatal("Gin server failed to run: %v", err)
	}
}

func findClusterById(clusterId string) (Cluster, bool) {
	for _, cluster := range clusters {
		if cluster.ClusterID.Hex() == clusterId {
			return cluster, true
		}
	}
	return Cluster{}, false
}
