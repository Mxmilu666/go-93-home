package source

import (
	"context"
	"fmt"
	"time"

	"anythingathome-golang/source/logger"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Cluster 表示 cluster 集合中的文档结构
type Cluster struct {
	ClusterID     bson.ObjectID `bson:"_id"`
	ClusterSecret string        `bson:"clusterSecret"`
	Name          string        `bson:"name"`
	EndPoint      string        `bson:"endpoint"`
	CreateAt      bson.DateTime `bson:"createAt"`
	IsEnable      bool          `bson:"isEnable"`
	IsBanned      bool          `bson:"isBanned"`
	Byoc          bool          `bson:"byoc"`
	Flavor        any           `bson:"flavor"`
}

type CertInfo struct {
	Id            bson.ObjectID `bson:"_id"`
	ClusterCert   string        `bson:"cluster_cert"`
	ClusterKey    string        `bson:"cluster_key"`
	ClusterExpiry time.Time     `bson:"cluster_expiry"`
}

var DatabaseName = "anythingathome"
var ClusterCollection = "cluster"
var FilesCollection = "files"
var TrafficCollection = "cluster_traffic"
var CertCollection = "cluster_cert"

// SetupDatabase 连接到 MongoDB
func SetupDatabase(uri string) (*mongo.Client, error) {
	clientOptions := options.Client().ApplyURI(uri)

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, err
	}

	// 检查连接
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, err
	}

	logger.Info("Connected to MongoDB")
	return client, nil
}

// EnsureCollection 确保指定的集合存在
func EnsureCollection(client *mongo.Client, dbName, collectionName string) error {
	collectionNames, err := client.Database(dbName).ListCollectionNames(context.TODO(), bson.M{})
	if err != nil {
		return err
	}

	// 检查集合是否存在
	collectionExists := false
	for _, name := range collectionNames {
		if name == collectionName {
			collectionExists = true
			break
		}
	}

	// 如果集合不存在，则创建集合
	if !collectionExists {
		err := client.Database(dbName).CreateCollection(context.TODO(), collectionName)
		if err != nil {
			return err
		}
		logger.Debug("Collection %s created successfully", collectionName)
	} else {
		logger.Debug("Collection %s already exists. Skip", collectionName)
	}

	return nil
}

// GetDocuments 从指定的集合中读取文档并解码为指定的类型 爱来自ChatGpt
func GetDocuments[T any](client *mongo.Client, dbName, collectionName string, filter interface{}, lastModified int64) ([]T, error) {
	collection := client.Database(dbName).Collection(collectionName)
	findOptions := options.Find()

	// 构建过滤器
	if filter == nil {
		filter = bson.M{}
	}

	// 如果 lastModified 不为 0，则将其添加到过滤器中
	// 使用 mtime 字段和 $gt 运算符来匹配修改时间大于 lastModified 的文件
	// 这样也能兼容 cluster 的查询
	if lastModified > 0 {
		lastModifiedTime := time.UnixMilli(lastModified)
		filter = bson.M{
			"$and": []bson.M{
				filter.(bson.M), // 原有的过滤器条件
				{"mtime": bson.M{"$gt": lastModifiedTime}}, // mtime 大于 lastModified
			},
		}
	}

	cursor, err := collection.Find(context.TODO(), filter, findOptions)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var results []T
	for cursor.Next(context.TODO()) {
		var elem T
		err := cursor.Decode(&elem)
		if err != nil {
			return nil, err
		}
		results = append(results, elem)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// 获取节点
func GetClusterById(client *mongo.Client, dbName, collectionName string, id bson.ObjectID) (*Cluster, error) {
	collection := client.Database(dbName).Collection(collectionName)

	var cluster Cluster
	err := collection.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&cluster)
	if err != nil {
		return nil, err
	}

	return &cluster, nil
}

// 查询文件
func GetFileFromDB(client *mongo.Client, dbName, collectionName, syncSource, fileName string) (*FileInfo, error) {
	collection := client.Database(dbName).Collection(collectionName)

	var fileRecord FileInfo
	filter := bson.M{"syncSource": syncSource, "fileName": fileName}
	err := collection.FindOne(context.TODO(), filter).Decode(&fileRecord)
	if err != nil {
		return nil, err
	}

	return &fileRecord, nil
}

// 更新节点信息
func UpdateClusterFieldsById(client *mongo.Client, dbName, collectionName string, id bson.ObjectID, updates bson.M) error {
	collection := client.Database(dbName).Collection(collectionName)

	// 使用 $set 操作符更新文档
	update := bson.M{
		"$set": updates,
	}

	// 根据 _id 更新文档
	_, err := collection.UpdateOne(context.TODO(), bson.M{"_id": id}, update)
	if err != nil {
		return err
	}

	return nil
}

// 更新证书信息
func UpdateCertFieldsById(client *mongo.Client, dbName, collectionName string, id bson.ObjectID, updates bson.M) error {
	collection := client.Database(dbName).Collection(collectionName)

	// 使用 $set 操作符更新文档
	update := bson.M{
		"$set": updates,
	}

	// 根据 clusterId 更新文档，如果不存在则新建
	_, err := collection.UpdateOne(context.TODO(), bson.M{"clusterId": id}, update, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}

	return nil
}

// 从数据库中随机获取一个文件
func GetRandomFile(client *mongo.Client, dbName, collectionName string) (*FileInfo, error) {
	collection := client.Database(dbName).Collection(collectionName)

	// 使用 $sample 获取随机文件
	pipeline := mongo.Pipeline{
		{{Key: "$sample", Value: bson.D{{Key: "size", Value: 1}}}},
	}

	cursor, err := collection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	if cursor.Next(context.TODO()) {
		var file FileInfo
		err := cursor.Decode(&file)
		if err != nil {
			return nil, err
		}
		return &file, nil
	}

	return nil, fmt.Errorf("no file found")
}

// 查询 cert
func GetCertOrRequest(client *mongo.Client, dbName, collectionName string, clusterId bson.ObjectID) (CertInfo, bool, error) {
	collection := client.Database(dbName).Collection(collectionName)

	// 查询条件
	var result CertInfo

	err := collection.FindOne(context.TODO(), bson.M{"clusterId": clusterId}).Decode(&result)
	if err != nil {
		return CertInfo{}, false, err // 返回空结构体
	}

	// 判断 cluster_cert 是否存在以及 cluster_expiry 是否超过当前时间
	if result.ClusterCert != "" && result.ClusterExpiry.After(time.Now()) {
		return result, true, nil
	}

	// 条件不满足，返回空结构体和 false
	return CertInfo{}, false, nil
}

// 干掉所有节点
func UpdateIsEnable(client *mongo.Client, databaseName, collectionName string) error {
	collection := client.Database(databaseName).Collection(collectionName)

	filter := map[string]interface{}{} // 匹配所有文档
	update := map[string]interface{}{
		"$set": map[string]interface{}{
			"isEnable": false,
		},
	}

	_, err := collection.UpdateMany(context.TODO(), filter, update)
	return err
}
