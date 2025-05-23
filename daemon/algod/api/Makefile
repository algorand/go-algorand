# Allow overriding swagger-converter API, e.g. for use with local container
SWAGGER_CONVERTER_API ?= https://converter.swagger.io

GEN := \
 server/v2/generated/nonparticipating/public/routes.go \
 server/v2/generated/nonparticipating/private/routes.go \
 server/v2/generated/participating/public/routes.go \
 server/v2/generated/participating/private/routes.go \
 server/v2/generated/data/routes.go \
 server/v2/generated/experimental/routes.go \
 server/v2/generated/model/types.go

all:	$(GEN)

# `make generate` exists because the old Makefile was written in a way
# that presumed oapi-codegen was already installed. CI used `make
# generate` to install it first.  Now `go run` makes everything work
# no matter what.  We could move to `go tool` later, if we want the
# versioning to be controlled in go.mod instead of here.
generate: all

OAPI := go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1

# Pattern rule for all routes.go generation
%/routes.go: %/routes.yml algod.oas3.yml
	$(OAPI) -config $^

# Only one types.go, but it's still more succinct to use a pattern
%/types.go: %/types.yml algod.oas3.yml
	$(OAPI) -config $^

# We use Makefile as a dependency here so everything gets rebuilt when you mess with how things are built.
algod.oas3.yml:	algod.oas2.json Makefile
	jq < $< > /dev/null  # fail with a nice explantion if json is malformed
	! grep '"type": "number"' $<  # Don't use the number type. Use integer (and format uint64 usually)
	curl -s -X POST "$(SWAGGER_CONVERTER_API)/api/convert" -H "accept: application/json" -H "Content-Type: application/json" -d @./$< -o .3tmp.json
	python3 jsoncanon.py < .3tmp.json > $@
	rm -f .3tmp.json

clean:
	rm -rf $(GEN) algod.oas3.yml
