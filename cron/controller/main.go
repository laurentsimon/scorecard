// Copyright 2021 Security Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main implements the PubSub controller.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ossf/scorecard/v4/clients"
	"github.com/ossf/scorecard/v4/cron/config"
	"github.com/ossf/scorecard/v4/cron/data"
	"github.com/ossf/scorecard/v4/cron/pubsub"
	"github.com/ossf/scorecard/v4/pkg"
)

var headSHA = clients.HeadSHA

func publishToRepoRequestTopic(iter data.Iterator, topicPublisher pubsub.Publisher,
	shardSize int, datetime time.Time,
) (int32, error) {
	var shardNum int32
	request := data.ScorecardBatchRequest{
		JobTime:  timestamppb.New(datetime),
		ShardNum: &shardNum,
	}

	// Create and send batch requests of repoURLs of size `ShardSize`:
	// * Iterate through incoming repoURLs until `request` has len(Repos) of size `ShardSize`.
	// * Publish request to PubSub topic.
	// * Clear request.Repos and increment shardNum.
	for iter.HasNext() {
		repoURL, err := iter.Next()
		if err != nil {
			return shardNum, fmt.Errorf("error reading repoURL: %w", err)
		}
		request.Repos = append(request.GetRepos(), &data.Repo{
			Url: &repoURL.Repo,
			// TODO(controller): pass in non-HEAD commitSHA here.
			Commit:   &headSHA,
			Metadata: repoURL.Metadata.ToString(),
		})
		if len(request.GetRepos()) < shardSize {
			continue
		}
		if err := topicPublisher.Publish(&request); err != nil {
			return shardNum, fmt.Errorf("error running topicPublisher.Publish: %w", err)
		}
		request.Repos = nil
		shardNum++
	}
	// Check if more repoURLs are pending to be sent in `request`.
	if len(request.GetRepos()) > 0 {
		if err := topicPublisher.Publish(&request); err != nil {
			return shardNum, fmt.Errorf("error running topicPublisher.Publish: %w", err)
		}
	} else {
		// shardNum incremented for an empty shard, decrement.
		shardNum--
	}

	if err := topicPublisher.Close(); err != nil {
		return shardNum, fmt.Errorf("error running topicPublisher.Close: %w", err)
	}
	return shardNum, nil
}

func main() {
	ctx := context.Background()
	t := time.Now()

	if len(os.Args) != 2 {
		panic("must provide a single argument")
	}

	inFile, err := os.OpenFile(os.Args[1], os.O_RDONLY, 0o644)
	if err != nil {
		panic(err)
	}
	reader, err := data.MakeIteratorFrom(inFile)
	if err != nil {
		panic(err)
	}

	topic, err := config.GetRequestTopicURL()
	if err != nil {
		panic(err)
	}
	topicPublisher, err := pubsub.CreatePublisher(ctx, topic)
	if err != nil {
		panic(err)
	}

	shardSize, err := config.GetShardSize()
	if err != nil {
		panic(err)
	}

	bucket, err := config.GetResultDataBucketURL()
	if err != nil {
		panic(err)
	}

	bucket2, err := config.GetResultDataBucketURLV2()
	if err != nil {
		panic(err)
	}

	rawBucket, err := config.GetRawResultDataBucketURL()
	if err != nil {
		panic(err)
	}

	shardNum, err := publishToRepoRequestTopic(reader, topicPublisher, shardSize, t)
	if err != nil {
		panic(err)
	}
	// Populate `.shard_metadata` file.
	metadata := data.ShardMetadata{
		NumShard:  new(int32),
		ShardLoc:  new(string),
		CommitSha: new(string),
	}
	*metadata.NumShard = (shardNum + 1)
	*metadata.ShardLoc = bucket + "/" + data.GetBlobFilename("", t)
	*metadata.CommitSha = pkg.GetCommit()
	metadataJSON, err := protojson.Marshal(&metadata)
	if err != nil {
		panic(fmt.Errorf("error during protojson.Marshal: %w", err))
	}
	err = data.WriteToBlobStore(ctx, bucket, data.GetShardMetadataFilename(t), metadataJSON)
	if err != nil {
		panic(fmt.Errorf("error writing to BlobStore: %w", err))
	}

	// UPGRADEv2: to remove.
	*metadata.ShardLoc = bucket2 + "/" + data.GetBlobFilename("", t)
	metadataJSON, err = protojson.Marshal(&metadata)
	if err != nil {
		panic(fmt.Errorf("error during protojson.Marshal2: %w", err))
	}
	err = data.WriteToBlobStore(ctx, bucket2, data.GetShardMetadataFilename(t), metadataJSON)
	if err != nil {
		panic(fmt.Errorf("error writing to BlobStore2: %w", err))
	}

	// Raw data v0.
	*metadata.ShardLoc = rawBucket + "/" + data.GetBlobFilename("", t)
	metadataJSON, err = protojson.Marshal(&metadata)
	if err != nil {
		panic(fmt.Errorf("error during protojson.Marshal raw: %w", err))
	}
	err = data.WriteToBlobStore(ctx, rawBucket, data.GetShardMetadataFilename(t), metadataJSON)
	if err != nil {
		panic(fmt.Errorf("error writing to BlobStore raw v0: %w", err))
	}
}
