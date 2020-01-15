#!/usr/bin/env bash

# Path(s) are relative to the root of the Jenkins workspace.

ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$(cat scripts/release/tmp/instance)" bash go/src/github.com/algorand/go-algorand/scripts/release/controller/sign.sh

