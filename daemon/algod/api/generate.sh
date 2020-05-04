#!/usr/bin/env bash
set -e

rootdir=`dirname $0`
pushd ${rootdir}

cd ${rootdir}/../../..
$(GO111MODULE=on go get -u "github.com/algorand/oapi-codegen/...@v1.3.5-algorand4")

popd

# Convert v2 to v3
curl -s -X POST "https://converter.swagger.io/api/convert" -H "accept: application/json" -H "Content-Type: application/json" -d @./algod.oas2.json  -o 3.json

# Sort keys, format json and rename 3.json -> algod.oas3.yml
python3 -c "import json; import sys; json.dump(json.load(sys.stdin), sys.stdout, indent=2, sort_keys=True)" < 3.json > algod.oas3.yml

echo "generating code."
oapi-codegen -package generated -type-mappings integer=uint64 -generate types -exclude-tags=private,common -o ./server/v2/generated/types.go algod.oas3.yml
oapi-codegen -package generated -type-mappings integer=uint64 -generate server,spec -exclude-tags=private,common -o ./server/v2/generated/routes.go algod.oas3.yml
oapi-codegen -package private -type-mappings integer=uint64 -generate types -include-tags=private -o ./server/v2/generated/private/types.go algod.oas3.yml
oapi-codegen -package private -type-mappings integer=uint64 -generate server,spec -include-tags=private -o ./server/v2/generated/private/routes.go algod.oas3.yml
