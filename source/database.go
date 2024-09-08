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
	EndPort       int           `bson:"endport"`
	CreateAt      bson.DateTime `bson:"createAt"`
	isBanned      bool          `bson:"isBanned"`
}

// SetupDatabase 连接到 MongoDB
func SetupDatabase(address string, port int, username, password string) (*mongo.Client, error) {
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%d", username, password, address, port)
	clientOptions := options.Client().ApplyURI(uri)

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, err
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, err
	}

	logger.Info("Connected to MongoDB")
	return client, nil
}

// EnsureClusterCollection 确保 CLUSTER 集合存在
func EnsureClusterCollection(client *mongo.Client, dbName, collectionName string) error {
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

// GetClusters 从 cluster 集合中读取所有文档
func GetClusters(client *mongo.Client, dbName, collectionName string) ([]Cluster, error) {
	collection := client.Database(dbName).Collection(collectionName)
	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var clusters []Cluster
	for cursor.Next(context.TODO()) {
		var cluster Cluster
		err := cursor.Decode(&cluster)
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, cluster)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return clusters, nil
}
