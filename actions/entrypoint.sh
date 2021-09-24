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

# ACTIONS_RUNTIME_TOKEN has token
# GITHUB_EVENT_PATH has json file for the event
# GITHUB_SHA
# GITHUB_WORKSPACE has the downaloded repo
# GITHUB_EVENT_NAME

echo $PWD
echo "--"
ls

# echo "--"
# sh -c "echo SCORECARD_ENV = $SCORECARD_ENV"
# id
# sh -c "echo github event is: $GITHUB_EVENT_NAME"
# sh -c "echo sarif file: $INPUT_SARIF_FILE"
# sh -c "echo policy file: $INPUT_POLICY_FILE"
# echo "workspace content:" && ls "$GITHUB_WORKSPACE"
# jq '.' "$GITHUB_EVENT_PATH"
# echo "--"
# env
GITHUB_AUTH_TOKEN="$ACTIONS_RUNTIME_TOKEN"
echo "tok:$GITHUB_AUTH_TOKEN"
echo "-- scorecard now!!"
#./scorecard --checks Code-Review --format sarif | jq '.'
#curl www.google.com
echo "end scoecard"
