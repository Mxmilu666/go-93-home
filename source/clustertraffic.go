package source

import (
	"anythingathome-golang/source/logger"
	"context"
	"fmt"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type TrafficRecord struct {
	ClusterID      bson.ObjectID `json:"clusterId"`      // 节点或集群的唯一ID
	PendingTraffic int64         `json:"pendingTraffic"` // 给节点的流量
	Traffic        int64         `json:"traffic"`        // 节点上报的流量
	PendingRequest int64         `json:"pendingRequest"` // 给节点的请求数
	Request        int64         `json:"request"`        // 节点上报的请求数
	Timestamp      time.Time     `json:"timestamp"`      // 最后更新时间
}

type ClusterResponse struct {
	ClusterID bson.ObjectID `json:"_id"`
	Name      string        `json:"name"`
	CreateAt  bson.DateTime `json:"createAt"`
	IsBanned  bool          `json:"isBanned"`
	Byoc      bool          `json:"byoc"`
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

// 获取 ClusterTraffic 列表并按 PendRequest 排序
func GetClusterTrafficDetails(client *mongo.Client, dbName string) ([]TrafficRecord, error) {
	trafficCollection := client.Database(dbName).Collection("cluster_traffic")
	cursor, err := trafficCollection.Find(context.TODO(), bson.D{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var trafficList []TrafficRecord
	if err = cursor.All(context.TODO(), &trafficList); err != nil {
		return nil, err
	}

	// 按 PendRequest 排序
	sort.Slice(trafficList, func(i, j int) bool {
		return trafficList[i].PendingRequest > trafficList[j].PendingRequest
	})

	for _, traffic := range trafficList {
		_, err := GetClusterById(client, dbName, ClusterCollection, traffic.ClusterID)
		if err != nil {
			logger.Error("Error fetching cluster:", err)
			continue
		}
	}

	return trafficList, nil
}
