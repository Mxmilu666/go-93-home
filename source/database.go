package source

import (
	"context"
	"fmt"

	"open93athome-golang/source/logger"

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
	IsBanned      bool          `bson:"isBanned"`
	Byoc          bool          `bson:"byoc"`
	Flavor        any           `bson:"flavor"`
}

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
func GetDocuments[T any](client *mongo.Client, dbName, collectionName string, filter interface{}) ([]T, error) {
	collection := client.Database(dbName).Collection(collectionName)
	findOptions := options.Find()

	// 如果过滤器为 nil，则将其设置为空文档
	if filter == nil {
		filter = bson.D{}
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
