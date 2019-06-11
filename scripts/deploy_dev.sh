#!/usr/bin/env bash

cd ${GOPATH}/src/github.com/algorand/go-algorand

scripts/deploy_version.sh $(./scripts/compute_branch.sh) $(./scripts/osarchtype.sh)
