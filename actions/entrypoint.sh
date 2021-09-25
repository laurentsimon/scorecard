#!/bin/sh -le
# Copyright 2021 Security Scorecard Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# https://docs.github.com/en/actions/learn-github-actions/environment-variables
# GITHUB_EVENT_PATH has json file for the event
# GITHUB_SHA
# GITHUB_WORKSPACE has the downaloded repo
# GITHUB_EVENT_NAME

# docker build . -f actions/Dockerfile -t laurentsimon/scorecard-action:latest
# docker run -e INPUT_SARIF_FILE=results.sarif -e GITHUB_WORKSPACE=/src -e INPUT_POLICY_FILE="policy-test.yaml" -e INPUT_REPO_TOKEN=$GITHUB_AUTH_TOKEN -e GITHUB_REPOSITORY="ossf/scorecard" laurentsimon/scorecard-action:latest
# 
echo $PWD
echo "--"
ls

# echo "--"
# id
sh -c "echo github event is: $GITHUB_EVENT_NAME"
sh -c "echo sarif file: $INPUT_SARIF_FILE"
sh -c "echo policy file: $INPUT_POLICY_FILE"
# echo "workspace content:" && ls "$GITHUB_WORKSPACE"
# jq '.' "$GITHUB_EVENT_PATH"
echo "--"
env
#export GITHUB_AUTH_TOKEN="$ACTIONS_RUNTIME_TOKEN"
export GITHUB_AUTH_TOKEN="$INPUT_REPO_TOKEN"
export SCORECARD_V3=1
export SCORECARD_POLICY_FILE="$INPUT_POLICY_FILE"
export SCORECARD_SARIF_FILE="$INPUT_SARIF_FILE"

#TODO: set SCORECARD_ENV="github-actions" if GITHUB_ACTIONS set to true

echo "tok:$GITHUB_AUTH_TOKEN"
echo "-- scorecard now!!"
#./scorecard --checks Code-Review --format sarif | jq '.'
#curl www.google.com
# TODO: check saif file and policy files.
# TODO: validate branch GITHUB_REF
cd "$GITHUB_WORKSPACE"
/src/scorecard --repo="$GITHUB_REPOSITORY" --format sarif --show-details --policy="$SCORECARD_POLICY_FILE" > "$SCORECARD_SARIF_FILE"
cat "$SCORECARD_SARIF_FILE"
jq '.' "$SCORECARD_SARIF_FILE"
echo "end scoecard"
#echo docker run -e GITHUB_AUTH_TOKEN="$ACTIONS_RUNTIME_TOKEN" gcr.io/openssf/scorecard:stable --repo="$GITHUB_REPOSITORY" --format json
