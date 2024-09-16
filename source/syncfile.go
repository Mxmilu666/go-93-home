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
    LocalDir   string        `bson:"localDir"`
    Hash       string        `bson:"hash"`
    Size       int64         `bson:"size"`
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

    var filePaths []string
    fullPathMap := make(map[string]string)
    err := filepath.Walk(syncSource.DestDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if info.IsDir() && strings.Contains(path, ".git") {
            return filepath.SkipDir
        }
        if !info.IsDir() {
            relativePath := strings.TrimPrefix(path, syncSource.DestDir)
            relativePath = strings.TrimPrefix(relativePath, string(os.PathSeparator))
            filePaths = append(filePaths, relativePath)
            fullPathMap[relativePath] = path
        }
        return nil
    })
    if err != nil {
        return err
    }

    bar := progressbar.NewOptions(len(filePaths),
        progressbar.OptionSetWidth(15),
        progressbar.OptionSetDescription("Syncing files"),
        progressbar.OptionShowCount(),
        progressbar.OptionShowBytes(true),
    )

    for relativePath, fullPath := range fullPathMap {
        wg.Add(1)
        go func(path, fullPath string) {
            defer wg.Done()
            fileInfoStat, err := os.Stat(fullPath)
            if err != nil {
                logger.Error("Error getting file info for %s: %v", fullPath, err)
                return
            }
            fileSize := fileInfoStat.Size()

            hash, err := ComputeFileHash(fullPath)
            if err != nil {
                logger.Error("Error computing hash for file %s: %v", fullPath, err)
                return
            }

            var existingFile FileInfo
            err = collection.FindOne(context.TODO(), bson.M{"fileName": path}).Decode(&existingFile)
            if err == nil && existingFile.Hash == hash && existingFile.Size == fileSize {
                bar.Add(1)
                return
            }

            fileInfo := FileInfo{
                FileName:   path,
                LocalDir:   fullPath,
                Hash:       hash,
                Size:       fileSize,
                MTime:      bson.DateTime(time.Now().UnixMilli()),
                SyncSource: syncSource.NAME,
            }

            _, err = collection.UpdateOne(
                context.TODO(),
                bson.M{"fileName": path},
                bson.M{"$set": fileInfo},
                options.Update().SetUpsert(true),
            )
            if err != nil {
                logger.Error("Error syncing file %s: %v", fullPath, err)
                return
            }

            bar.Add(1)
        }(relativePath, fullPath)
    }

    wg.Wait()
    bar.Finish()

    return nil
}