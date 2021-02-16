GOPATH	:= $(shell go env GOPATH)
GOPATH1	:= $(firstword $(subst :, ,$(GOPATH)))

# `make all` or just `make` should be appropriate for dev work
all:	server/v2/generated/types.go server/v2/generated/routes.go server/v2/generated/private/types.go server/v2/generated/private/routes.go

# `make generate` should be able to replace old `generate.sh` script and be appropriate for build system use
generate:	oapi-codegen all

server/v2/generated/types.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -package generated -type-mappings integer=uint64 -generate types -exclude-tags=private,common -o ./server/v2/generated/types.go algod.oas3.yml

server/v2/generated/routes.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -package generated -type-mappings integer=uint64 -generate server,spec -exclude-tags=private,common -o ./server/v2/generated/routes.go algod.oas3.yml

server/v2/generated/private/types.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -package private -type-mappings integer=uint64 -generate types -include-tags=private -o ./server/v2/generated/private/types.go algod.oas3.yml

server/v2/generated/private/routes.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -package private -type-mappings integer=uint64 -generate server,spec -include-tags=private -o ./server/v2/generated/private/routes.go algod.oas3.yml

algod.oas3.yml:	algod.oas2.json
	curl -s -X POST "https://converter.swagger.io/api/convert" -H "accept: application/json" -H "Content-Type: application/json" -d @./algod.oas2.json -o .3tmp.json
	python3 jsoncanon.py < .3tmp.json > algod.oas3.yml
	rm -f .3tmp.json

oapi-codegen:	.PHONY
	GO111MODULE=on go get -u "github.com/algorand/oapi-codegen/...@v1.3.5-algorand5"

clean:
	rm -rf server/v2/generated/types.go server/v2/generated/routes.go server/v2/generated/private/types.go server/v2/generated/private/routes.go algod.oas3.yml

.PHONY:
