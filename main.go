package main

import (
	"fmt"
	"os"

	"open93athome-golang/source"
	"open93athome-golang/source/Helper"
	"open93athome-golang/source/logger"
)

func main() {
	fmt.Printf("Open93AtHome-Golang v0.0.1 \n")

	logger.InitLogger(logger.DEBUG, "[93@home-Go] ")
	logger.Info("Starting...")

	configFile := "config.yml"

	// 检查配置文件是否存在，如果不存在则创建默认配置文件
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		err := source.CreateDefaultConfig(configFile)
		if err != nil {
			logger.Error("Error creating default config file: %v", err)
			return
		}
		logger.Info("Created default config file. Please edit it with your configuration.")
		return
	}

	// 读取配置文件
	config, err := source.ReadConfig(configFile)
	if err != nil {
		logger.Error("Error reading config file: %v", err)
		return
	}

	// 初始化数据库
	database, err := source.SetupDatabase(
		config.Database.Address,
		config.Database.Port,
		config.Database.Username,
		config.Database.Password,
	)
	if err != nil {
		logger.Error("Error setting up database: %v", err)
		return
	}

	// 确保 CLUSTER 集合存在
	err = source.EnsureClusterCollection(database, "93athome", "cluster")
	if err != nil {
		logger.Error("Error ensuring cluster collection: %v", err)
		return
	}

	// 读取 cluster 集合中的所有数据
	clusters, err := source.GetClusters(database, "93athome", "cluster")
	if err != nil {
		logger.Error("Error getting clusters: %v", err)
		return
	}

	// 输出读取到的数据
	for _, cluster := range clusters {
		logger.Info("Cluster: %+v", cluster)
	}

	// 初始化 JWT
	Helper.GetInstance()

	// 启动服务器
	source.SetupServer(config.Server.Address, fmt.Sprintf("%d", config.Server.Port), database)
}
