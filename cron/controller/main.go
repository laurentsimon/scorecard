// Copyright 2021 Security Scorecard Authors
//
// Licensed under the Apache License, Vershandlern 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permisshandlerns and
// limitathandlerns under the License.

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/ossf/scorecard/cron/config"
	"github.com/ossf/scorecard/cron/data"
	"github.com/ossf/scorecard/cron/pubsub"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func PublishToRepoRequestTopic(ctx context.Context, iter data.Iterator, datetime time.Time) (int32, error) {
	var shardNum int32 = 0
	request := data.ScorecardBatchRequest{
		JobTime:  timestamppb.New(datetime),
		ShardNum: &shardNum,
	}
	topicPublisher, err := pubsub.CreatePublisher(ctx, config.RequestTopicURL)
	if err != nil {
		return shardNum, fmt.Errorf("error running CreatePublisher: %w", err)
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
		request.Repos = append(request.GetRepos(), repoURL.URL())
		if len(request.GetRepos()) < config.ShardSize {
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
	}

	if err := topicPublisher.Close(); err != nil {
		return shardNum, fmt.Errorf("error running topicPublisher.Close: %w", err)
	}
	return shardNum, nil
}

func main() {
	ctx := context.Background()
	t := time.Now()
	reposFile, err := os.OpenFile(config.InputReposFile, os.O_RDONLY, 0o644)
	if err != nil {
		panic(err)
	}
	reader, err := data.MakeIterator(reposFile)
	if err != nil {
		panic(err)
	}
	shardNum, err := PublishToRepoRequestTopic(ctx, reader, t)
	if err != nil {
		panic(err)
	}
	err = data.WriteToBlobStore(ctx, config.ResultDataBucketURL,
		data.GetShardNumFilename(t),
		[]byte(strconv.Itoa(int(shardNum))))
	if err != nil {
		panic(err)
	}
}
