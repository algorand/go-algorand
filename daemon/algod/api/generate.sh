#!/usr/bin/env bash
set -e

rootdir=`dirname $0`
pushd ${rootdir}

cd ${rootdir}/../../..
$(GO111MODULE=on go get -u "github.com/algorand/oapi-codegen/...@v1.3.5-algorand2")

popd

# Convert v2 to v3
curl -s -X POST "https://converter.swagger.io/api/convert" -H "accept: application/json" -H "Content-Type: application/json" -d @./algod.oas2.json  -o 3.json
python3 jsoncanon.py < 3.json > algod.oas3.yml
#cat 3.json | json_pp > algod.oas3.yml
rm 3.json
# The line below was removed, as it doesn't seem to be required anymore, and currently giving us portability issues.
#sed -i '' 's/\*.\*/application\/json/g' algod.oas3.yml

echo "generating code."
oapi-codegen -package generated -type-mappings integer=uint64 -generate types -exclude-tags=private -o ./server/v2/generated/types.go algod.oas3.yml
oapi-codegen -package generated -type-mappings integer=uint64 -generate server,spec -exclude-tags=private -o ./server/v2/generated/routes.go algod.oas3.yml
oapi-codegen -package private -type-mappings integer=uint64 -generate types -include-tags=private -o ./server/v2/generated/private/types.go algod.oas3.yml
oapi-codegen -package private -type-mappings integer=uint64 -generate server,spec -include-tags=private -o ./server/v2/generated/private/routes.go algod.oas3.yml
