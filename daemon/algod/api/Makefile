GOPATH	:= $(shell go env GOPATH)
GOPATH1	:= $(firstword $(subst :, ,$(GOPATH)))

# Allow overriding swagger-converter API, e.g. for use with local container
SWAGGER_CONVERTER_API ?= https://converter.swagger.io

# `make all` or just `make` should be appropriate for dev work
all:	server/v2/generated/model/types.go server/v2/generated/nonparticipating/public/routes.go server/v2/generated/nonparticipating/private/routes.go server/v2/generated/participating/public/routes.go server/v2/generated/participating/private/routes.go server/v2/generated/data/routes.go server/v2/generated/experimental/routes.go

# `make generate` should be able to replace old `generate.sh` script and be appropriate for build system use
generate:	oapi-codegen all

server/v2/generated/nonparticipating/public/routes.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -config ./server/v2/generated/nonparticipating/public/public_routes.yml algod.oas3.yml

server/v2/generated/nonparticipating/private/routes.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -config ./server/v2/generated/nonparticipating/private/private_routes.yml algod.oas3.yml

server/v2/generated/participating/public/routes.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -config ./server/v2/generated/participating/public/public_routes.yml algod.oas3.yml

server/v2/generated/participating/private/routes.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -config ./server/v2/generated/participating/private/private_routes.yml algod.oas3.yml


server/v2/generated/data/routes.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -config ./server/v2/generated/data/data_routes.yml algod.oas3.yml

server/v2/generated/experimental/routes.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -config ./server/v2/generated/experimental/experimental_routes.yml algod.oas3.yml

server/v2/generated/model/types.go:	algod.oas3.yml
	$(GOPATH1)/bin/oapi-codegen -config ./server/v2/generated/model/model_types.yml algod.oas3.yml

algod.oas3.yml:	algod.oas2.json
	jq < algod.oas2.json > /dev/null	# fail with a nice explantion if json is malformed
	curl -s -X POST "$(SWAGGER_CONVERTER_API)/api/convert" -H "accept: application/json" -H "Content-Type: application/json" -d @./algod.oas2.json -o .3tmp.json
	python3 jsoncanon.py < .3tmp.json > algod.oas3.yml
	rm -f .3tmp.json

oapi-codegen:	.PHONY
	../../../scripts/buildtools/install_buildtools.sh -o github.com/algorand/oapi-codegen -c github.com/algorand/oapi-codegen/cmd/oapi-codegen

clean:
	rm -rf server/v2/generated/model/types.go server/v2/generated/nonparticipating/public/routes.go server/v2/generated/nonparticipating/private/routes.go server/v2/generated/participating/public/routes.go server/v2/generated/participating/private/routes.go server/v2/generated/data/routes.go algod.oas3.yml

.PHONY:
