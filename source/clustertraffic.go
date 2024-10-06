package source

import (
	"anythingathome-golang/source/logger"
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type TrafficRecord struct {
	ClusterID      bson.ObjectID `json:"clusterId"`      // 节点ID
	Traffic        int64         `json:"traffic"`        // 节点上报的流量
	Request        int64         `json:"request"`        // 节点上报的请求数
	PendingTraffic int64         `json:"pendingTraffic"` // 给节点的流量
	PendingRequest int64         `json:"pendingRequest"` // 给节点的请求数
	Timestamp      time.Time     `json:"timestamp"`      // 最后更新时间
}

type ClusterResponse struct {
	ClusterID bson.ObjectID `json:"_id"`
	Name      string        `json:"name"`
	CreateAt  bson.DateTime `json:"createAt"`
	IsEnable  bool          `json:"isEnable"`
	IsBanned  bool          `json:"isBanned"`
	Flavor    any           `json:"flavor"`
	Metric    any           `json:"metric"`
}

// RecordTrafficToNode 传入增量数据，更新给节点的流量和请求数
func RecordTrafficToNode(client *mongo.Client, dbName, collectionName string, clusterID bson.ObjectID, PendingTraffic, PendingRequest int64) error {
	collection := client.Database(dbName).Collection(collectionName)

	now := time.Now()

	// 过滤条件：使用 clusterID 唯一标识
	filter := bson.M{"clusterId": clusterID}

	// 构造增量更新
	update := bson.M{
		"$inc": bson.M{ // 增加给节点的流量和请求数
			"pendTraffic": PendingTraffic,
			"pendRequest": PendingRequest,
		},
		"$set": bson.M{ // 更新 timestamp 字段为当前时间
			"timestamp": now,
		},
		"$setOnInsert": bson.M{ // 如果文档不存在，插入时设置 clusterId
			"clusterId": clusterID,
		},
	}

	// 使用 upsert 操作：如果文档不存在则插入，存在则增量更新
	opts := options.Update().SetUpsert(true)
	_, err := collection.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to update traffic and request data to node: %w", err)
	}

	return nil
}

// RecordTrafficFromNode 传入增量数据，更新节点上报的流量和请求数
func RecordTrafficFromNode(client *mongo.Client, dbName, collectionName string, clusterID bson.ObjectID, Traffic, Request int64) error {
	collection := client.Database(dbName).Collection(collectionName)

	now := time.Now()

	// 过滤条件：使用 clusterID 唯一标识
	filter := bson.M{"clusterId": clusterID}

	// 构造增量更新
	update := bson.M{
		"$inc": bson.M{ // 增加节点上报的流量和请求数
			"traffic": Traffic,
			"request": Request,
		},
		"$set": bson.M{ // 更新 timestamp 字段为当前时间
			"timestamp": now,
		},
		"$setOnInsert": bson.M{ // 如果文档不存在，插入时设置 clusterId
			"clusterId": clusterID,
		},
	}

	// 使用 upsert 操作：如果文档不存在则插入，存在则增量更新
	opts := options.Update().SetUpsert(true)
	_, err := collection.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to update traffic and request data reported by node: %w", err)
	}

	return nil
}

// 获取 ClusterTraffic
func GetClusterTrafficDetails(client *mongo.Client, dbName, ClusterCollection, TrafficCollection string) ([]ClusterResponse, error) {
	trafficCollection := client.Database(dbName).Collection(TrafficCollection)

	// 使用聚合查询同时获取 ClusterTraffic 和相关 Cluster 数据
	pipeline := mongo.Pipeline{
		{
			{Key: "$lookup", Value: bson.M{
				"from":         ClusterCollection,
				"localField":   "clusterId",
				"foreignField": "_id",
				"as":           "cluster_info",
			}},
		},
		{
			{Key: "$unwind", Value: bson.M{"path": "$cluster_info"}},
		},
		{
			{Key: "$sort", Value: bson.M{"pendRequest": -1}},
		},
	}

	cursor, err := trafficCollection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var responses []ClusterResponse
	for cursor.Next(context.TODO()) {
		var result struct {
			ClusterInfo struct {
				ID       bson.ObjectID `bson:"_id"`
				Name     string        `bson:"name"`
				CreateAt bson.DateTime `bson:"createAt"`
				IsEnable bool          `bson:"isEnable"`
				IsBanned bool          `bson:"isBanned"`
				Flavor   any           `bson:"flavor"`
			} `bson:"cluster_info"`
			Request     int   `bson:"request"`
			Traffic     int   `bson:"traffic"`
			PendRequest int   `bson:"pendRequest"`
			PendTraffic int64 `bson:"pendTraffic"`
		}

		if err := cursor.Decode(&result); err != nil {
			logger.Error("Error decoding response:", err)
			continue
		}

		response := ClusterResponse{
			ClusterID: result.ClusterInfo.ID,
			Name:      result.ClusterInfo.Name,
			CreateAt:  result.ClusterInfo.CreateAt,
			IsEnable:  result.ClusterInfo.IsEnable,
			IsBanned:  result.ClusterInfo.IsBanned,
			Flavor:    result.ClusterInfo.Flavor,
			Metric: bson.M{
				"request":     result.Request,
				"traffic":     result.Traffic,
				"pendRequest": result.PendRequest,
				"pendTraffic": result.PendTraffic,
			},
		}

		responses = append(responses, response)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return responses, nil
}
