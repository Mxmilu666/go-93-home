package main

import (
	"context"
	"fmt"
	"os"

	"anythingathome-golang/source"
	"anythingathome-golang/source/Helper"
	"anythingathome-golang/source/logger"
)

func main() {
	fmt.Printf("AnythingAtHome-golang v0.0.1 \n")

	logger.InitLogger(logger.DEBUG, "[Anything@Home-Go] ")
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
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%d",
		config.Database.Username,
		config.Database.Password,
		config.Database.Address,
		config.Database.Port,
	)
	database, err := source.SetupDatabase(uri)
	if err != nil {
		logger.Error("Error setting up database: %v", err)
		return
	}

	defer func() {
		if err = database.Disconnect(context.TODO()); err != nil {
			logger.Error("Error disconnecting from database: %v", err)
		}
	}()

	// 确保需要的集合存在
	err = source.EnsureCollection(database, source.DatabaseName, source.ClusterCollection)
	if err != nil {
		logger.Error("Error ensuring clusters collection: %v", err)
		return
	}

	err = source.EnsureCollection(database, source.DatabaseName, source.FilesCollection)
	if err != nil {
		logger.Error("Error ensuring files collection: %v", err)
		return
	}

	err = source.EnsureCollection(database, source.DatabaseName, source.TrafficCollection)
	if err != nil {
		logger.Error("Error ensuring clustertraffic collection: %v", err)
		return
	}

	// 输出同步源的数量和详细信息
	logger.Info("Number of sync sources: %d", len(config.SyncSources))
	for i, syncSource := range config.SyncSources {
		logger.Info("Sync Source %d [%s]: URL=%s, Branch=%s, DestDir=%s", i+1, syncSource.NAME, syncSource.URL, syncSource.Branch, syncSource.DestDir)
		// Clone or pull the Git repo
		err := source.CloneOrPullRepo(syncSource.URL, syncSource.Branch, syncSource.DestDir)
		if err != nil {
			logger.Error("Error syncing repository %s: %v", syncSource.URL, err)
			return
		}

		// 同步文件并将文件信息写入 MongoDB
		err = source.SyncFiles(database, syncSource)
		if err != nil {
			logger.Error("Error syncing files: %v", err)
			return
		}
	}

	// 获取 clusters 和 files 数据
	clusters, err := source.GetDocuments[source.Cluster](database, source.DatabaseName, source.ClusterCollection, nil, 0)
	if err != nil {
		logger.Error("Error getting cluster: %v", err)
		return
	}

	// 输出 clusters 信息
	for _, cluster := range clusters {
		logger.Info("Cluster: %+v", cluster)
	}

	// 初始化 JWT
	Helper.GetInstance()

	// 启动服务器
	source.SetupServer(config.Server.Address, fmt.Sprintf("%d", config.Server.Port), database)
}
