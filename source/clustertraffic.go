package source

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type TrafficRecord struct {
	ClusterID      bson.ObjectID `bson:"clusterId"`      // 节点或集群的唯一ID
	Timestamp      time.Time     `bson:"timestamp"`      // 最后更新时间
	PendingTraffic int64         `bson:"pendingTraffic"` // 给节点的流量
	Traffic        int64         `bson:"traffic"`        // 节点上报的流量
	PendingRequest int64         `bson:"pendingRequest"` // 给节点的请求数
	Request        int64         `bson:"request"`        // 节点上报的请求数
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
			"pendingTraffic": PendingTraffic,
			"pendingRequest": PendingRequest,
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
			"trafficReportedByNode": Traffic,
			"requestReportedByNode": Request,
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
