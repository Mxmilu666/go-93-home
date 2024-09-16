package source

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"open93athome-golang/source/logger"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// FileInfo 表示 files 集合中的文档结构
type FileInfo struct {
	FileName   string        `bson:"fileName"`
	Hash       string        `bson:"hash"`
	Size       int64         `bson:"size"` // 修改类型为 int64，并修正 bson 标签
	MTime      bson.DateTime `bson:"mtime"`
	SyncSource string        `bson:"syncSource"`
}

func CloneOrPullRepo(repoURL, branch, destDir string) error {
	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		cmd := exec.Command("git", "clone", "--branch", branch, repoURL, destDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Printf("Cloning repository %s to %s\n", repoURL, destDir)
		return cmd.Run()
	}

	cmd := exec.Command("git", "-C", destDir, "pull", "origin", branch)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Pulling latest changes for repository %s in %s\n", repoURL, destDir)
	return cmd.Run()
}

// ComputeFileHash 计算文件的哈希值
func ComputeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha1.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// SyncFiles 同步文件并将文件信息写入 MongoDB
func SyncFiles(client *mongo.Client, syncSource SyncSourceConfig) error {
	collection := client.Database("93athome").Collection("files")
	var wg sync.WaitGroup

	// 收集文件路径
	var filePaths []string
	err := filepath.Walk(syncSource.DestDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 排除 .git 文件夹
		if info.IsDir() && strings.Contains(path, ".git") {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			filePaths = append(filePaths, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// 设置进度条
	bar := progressbar.NewOptions(len(filePaths),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetDescription("Syncing files"),
		progressbar.OptionShowCount(),
		progressbar.OptionShowBytes(true),
	)

	// 使用 goroutines 并行计算文件哈希并同步文件信息
	for _, filePath := range filePaths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()

			// 获取文件信息，包括大小
			fileInfoStat, err := os.Stat(path)
			if err != nil {
				logger.Error("Error getting file info for %s: %v", path, err)
				return
			}
			fileSize := fileInfoStat.Size() // 获取文件大小

			hash, err := ComputeFileHash(path)
			if err != nil {
				logger.Error("Error computing hash for file %s: %v", path, err)
				return
			}

			// 检查文件是否已存在且哈希值和大小相同
			var existingFile FileInfo
			err = collection.FindOne(context.TODO(), bson.M{"fileName": path}).Decode(&existingFile)
			if err == nil && existingFile.Hash == hash && existingFile.Size == fileSize {
				// 文件已存在且哈希值和大小相同，跳过
				bar.Add(1)
				return
			}

			fileInfo := FileInfo{
				FileName:   path,
				Hash:       hash,
				Size:       fileSize,                              // 将文件大小存储到数据库
				MTime:      bson.DateTime(time.Now().UnixMilli()), // 设置同步时间为当前时间
				SyncSource: syncSource.NAME,
			}

			_, err = collection.UpdateOne(
				context.TODO(),
				bson.M{"fileName": path},
				bson.M{"$set": fileInfo},
				options.Update().SetUpsert(true),
			)
			if err != nil {
				logger.Error("Error syncing file %s: %v", path, err)
				return
			}

			bar.Add(1) // 更新进度条
		}(filePath)
	}

	// 等待所有 goroutines 完成
	wg.Wait()
	bar.Finish()

	return nil
}
