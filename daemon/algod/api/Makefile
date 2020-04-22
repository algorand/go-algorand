all:	server/v2/generated/types.go server/v2/generated/routes.go server/v2/generated/private/types.go server/v2/generated/private/routes.go

server/v2/generated/types.go:	algod.oas3.yml
	oapi-codegen -package generated -type-mappings integer=uint64 -generate types -exclude-tags=private -o ./server/v2/generated/types.go algod.oas3.yml

server/v2/generated/routes.go:	algod.oas3.yml
	oapi-codegen -package generated -type-mappings integer=uint64 -generate server,spec -exclude-tags=private -o ./server/v2/generated/routes.go algod.oas3.yml

server/v2/generated/private/types.go:	algod.oas3.yml
	oapi-codegen -package private -type-mappings integer=uint64 -generate types -include-tags=private -o ./server/v2/generated/private/types.go algod.oas3.yml

server/v2/generated/private/routes.go:	algod.oas3.yml
	oapi-codegen -package private -type-mappings integer=uint64 -generate server,spec -include-tags=private -o ./server/v2/generated/private/routes.go algod.oas3.yml

algod.oas3.yml:	.3tmp.json
	python3 jsoncanon.py < .3tmp.json > algod.oas3.yml

.3tmp.json:	algod.oas2.json
	curl -s -X POST "https://converter.swagger.io/api/convert" -H "accept: application/json" -H "Content-Type: application/json" -d @./algod.oas2.json -o .3tmp.json

.PHONY:
