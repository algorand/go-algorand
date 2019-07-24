GOPATH		:= $(shell go env GOPATH)
export GOPATH
UNAME		:= $(shell uname)
SRCPATH     := $(shell pwd)

# If build number already set, use it - to ensure same build number across multiple platforms being built
BUILDNUMBER      ?= $(shell GOPATH=$(GOPATH) ./scripts/compute_build_number.sh)
COMMITHASH       := $(shell ./scripts/compute_build_commit.sh)
BUILDBRANCH      ?= $(shell ./scripts/compute_branch.sh)
BUILDCHANNEL     ?= $(shell ./scripts/compute_branch_channel.sh $(BUILDBRANCH))
DEFAULTNETWORK   ?= $(shell ./scripts/compute_branch_network.sh $(BUILDBRANCH))
DEFAULT_DEADLOCK ?= $(shell ./scripts/compute_branch_deadlock_default.sh $(BUILDBRANCH))

ifeq ($(UNAME), Linux)
EXTLDFLAGS := -static-libstdc++ -static-libgcc
endif

GOTAGS          := --tags "sqlite_unlock_notify sqlite_omit_load_extension"
GOTRIMPATH	:= $(shell go help build | grep -q .-trimpath && echo -trimpath)

GOLDFLAGS_BASE  := -X github.com/algorand/go-algorand/config.BuildNumber=$(BUILDNUMBER) \
		 -X github.com/algorand/go-algorand/config.CommitHash=$(COMMITHASH) \
		 -X github.com/algorand/go-algorand/config.Branch=$(BUILDBRANCH) \
		 -X github.com/algorand/go-algorand/config.DefaultDeadlock=$(DEFAULT_DEADLOCK) \
		 -extldflags \"$(EXTLDFLAGS)\"

GOLDFLAGS := $(GOLDFLAGS_BASE) \
		 -X github.com/algorand/go-algorand/config.Channel=$(BUILDCHANNEL)

SOURCES := $(shell go list ./... | grep -v /go-algorand/test/)

UNIT_TEST_SOURCES := $(sort $(shell go list ./... | grep -v /go-algorand/test/ | grep -v /go-algorand/vendor/ ))
E2E_TEST_SOURCES := $(shell cd test/e2e-go && go list ./...)

default: build

# tools

fmt:
	go fmt ./...

fix: build
	$(GOPATH)/bin/algofix `ls -d */ | grep -vw vendor`

fixcheck: build
	$(GOPATH)/bin/algofix -error `ls -d */ | grep -vw vendor`

lint: deps
	$(GOPATH)/bin/golint `go list ./...`

vend:
	$(GOPATH)/bin/vend

vet:
	go vet ./...

sanity: vet fix lint fmt

cover:
		go test $(GOTAGS) -coverprofile=cover.out $(UNIT_TEST_SOURCES)

prof:
	cd node && go test $(GOTAGS) -cpuprofile=cpu.out -memprofile=mem.out -mutexprofile=mutex.out

generate: deps
	PATH=$(GOPATH)/bin:$$PATH go generate ./...

# build our fork of libsodium, placing artifacts into crypto/lib/ and crypto/include/
crypto/lib/libsodium.a:
	cd crypto/libsodium-fork && \
		./autogen.sh && \
		./configure --disable-shared --prefix="$(SRCPATH)/crypto/" && \
		$(MAKE) && \
		$(MAKE) install

deps:
	./scripts/check_deps.sh

# artifacts

# Regenerate algod swagger spec files
ALGOD_API_SWAGGER_SPEC := daemon/algod/api/swagger.json
ALGOD_API_FILES := $(shell find daemon/algod/api/server/common -type f) \
	$(shell find daemon/algod/api/server/v1 -type f) \
	daemon/algod/api/server/router.go
ALGOD_API_SWAGGER_INJECT := daemon/algod/api/server/lib/bundledSpecInject.go

# Note that swagger.json requires the go-swagger dep.
$(ALGOD_API_SWAGGER_SPEC): $(ALGOD_API_FILES)
	$(info "regenerating swagger.json due to changes in algod/api/server")
	@cd daemon/algod/api && \
		PATH=$(GOPATH)/bin:$$PATH \
		go generate ./...
	@{ \
	echo "performing custom validation of swagger.json";\
	algodProblem=$$(cat $(ALGOD_API_SWAGGER_SPEC) | jq -c '.definitions[].properties | select(. != null) | with_entries(select(.value.type=="array" and .value.items.format=="uint8")) | select(. != {}) | keys[]');\
	if [ "$${algodProblem}" != "" ]; then\
		echo "detected uint8 array in algod/swagger.json:$${algodProblem}. Did you mean to use format: binary?";\
		echo "you will need to fix these swagger problems to allow build to proceed";\
		exit 1;\
	else\
		echo "custom validation succeeded";\
	fi;\
	} \

$(ALGOD_API_SWAGGER_INJECT): $(ALGOD_API_SWAGGER_SPEC)
	./daemon/algod/api/server/lib/bundle_swagger_json.sh

# Regenerate kmd swagger spec files
KMD_API_SWAGGER_SPEC := daemon/kmd/api/swagger.json
KMD_API_DIRS := $(shell find daemon/kmd/api/ -type d)
KMD_API_FILES := $(shell find daemon/kmd/api/ -type f | grep -v $(KMD_API_SWAGGER_SPEC))
KMD_API_SWAGGER_WRAPPER := kmdSwaggerWrappers.go
KMD_API_SWAGGER_INJECT := daemon/kmd/lib/kmdapi/bundledSpecInject.go

# Note that swagger.json requires the go-swagger dep.
$(KMD_API_SWAGGER_SPEC): $(KMD_API_DIRS) $(KMD_API_FILES)
	$(info "regenerating swagger.json due to changes in kmd")
	@cd daemon/kmd/lib/kmdapi && \
		python genSwaggerWrappers.py $(KMD_API_SWAGGER_WRAPPER) && \
		cd daemon/kmd && \
		PATH=$(GOPATH)/bin:$$PATH \
		go generate ./... && \
		rm daemon/kmd/lib/kmdapi/$(KMD_API_SWAGGER_WRAPPER)
	@{ \
	echo "performing custom validation of swagger.json";\
	kmdProblem=$$(cat $(KMD_API_SWAGGER_SPEC) | jq -c '.definitions[].properties | select(. != null) | with_entries(select(.value.type=="array" and .value.items.format=="uint8")) | select(. != {}) | keys[]');\
	if [ "$${kmdProblem}" != "" ]; then\
		echo "detected uint8 array in kmd/swagger.json:$${kmdProblem}. Did you mean to use format: binary?";\
		echo "you will need to fix these swagger problems to allow build to proceed";\
		exit 1;\
	else\
		echo "custom validation succeeded";\
	fi;\
	} \

$(KMD_API_SWAGGER_INJECT): $(KMD_API_SWAGGER_SPEC)
	daemon/kmd/lib/kmdapi/bundle_swagger_json.sh

# develop

build: buildsrc gen

buildsrc: crypto/lib/libsodium.a node_exporter NONGO_BIN deps $(ALGOD_API_SWAGGER_INJECT) $(KMD_API_SWAGGER_INJECT)
	go install $(GOTRIMPATH) $(GOTAGS) -ldflags="$(GOLDFLAGS)" $(SOURCES)
	go vet $(UNIT_TEST_SOURCES) $(E2E_TEST_SOURCES)

SOURCES_RACE := github.com/algorand/go-algorand/cmd/kmd

## Build binaries with the race detector enabled in them.
## This allows us to run e2e tests with race detection.
## We overwrite bin-race/kmd with a non -race version due to
## the incredible performance impact of -race on Scrypt.
build-race: build
	@mkdir -p $(GOPATH)/bin-race
	GOBIN=$(GOPATH)/bin-race go install $(GOTRIMPATH) $(GOTAGS) -race -ldflags="$(GOLDFLAGS)" $(SOURCES)
	GOBIN=$(GOPATH)/bin-race go install $(GOTRIMPATH) $(GOTAGS) -ldflags="$(GOLDFLAGS)" $(SOURCES_RACE)

NONGO_BIN_FILES=$(GOPATH)/bin/find-nodes.sh $(GOPATH)/bin/update.sh $(GOPATH)/bin/COPYING

NONGO_BIN: $(NONGO_BIN_FILES)

$(GOPATH)/bin/find-nodes.sh: scripts/find-nodes.sh

$(GOPATH)/bin/update.sh: cmd/updater/update.sh

$(GOPATH)/bin/COPYING: COPYING

$(GOPATH)/bin/%:
	cp -f $< $@

test: build
	go test $(GOTAGS) -race $(UNIT_TEST_SOURCES)

fulltest: build-race
	for PACKAGE_DIRECTORY in $(UNIT_TEST_SOURCES) ; do \
		go test $(GOTAGS) -timeout 2000s -race $$PACKAGE_DIRECTORY; \
	done

shorttest: build-race $(addprefix short_test_target_, $(UNIT_TEST_SOURCES))

$(addprefix short_test_target_, $(UNIT_TEST_SOURCES)): build
	@go test $(GOTAGS) -short -timeout 2000s -race $(subst short_test_target_,,$@)

integration: build-race
	./test/scripts/run_integration_tests.sh

testall: fulltest integration

# generated files we should make sure we clean
GENERATED_FILES := daemon/algod/api/bundledSpecInject.go \
	daemon/algod/api/lib/bundledSpecInject.go \
	daemon/kmd/lib/kmdapi/bundledSpecInject.go

clean:
	go clean -i ./...
	rm -f $(GOPATH)/bin/node_exporter
	rm -f $(GENERATED_FILES)
	cd crypto/libsodium-fork && \
		test ! -e Makefile || make clean
	rm -rf crypto/lib

# clean without crypto
cleango:
	go clean -i ./...
	rm -f $(GOPATH)/bin/node_exporter
	rm -f $(GENERATED_FILES)

# assign the phony target node_exporter the dependency of the actual executable.
node_exporter: $(GOPATH)/bin/node_exporter

# The recipe for making the node_exporter is by extracting it from the gzipped&tar file.
# The file is was taken from the S3 cloud and it traditionally stored at
# /travis-build-artifacts-us-ea-1.algorand.network/algorand/node_exporter/latest/node_exporter-stable-linux-x86_64.tar.gz
$(GOPATH)/bin/node_exporter:
	tar -xzvf installer/external/node_exporter-stable-$(shell ./scripts/ostype.sh)-$(shell uname -m | tr '[:upper:]' '[:lower:]').tar.gz -C $(GOPATH)/bin

# deploy

deploy:
	scripts/deploy_dev.sh

.PRECIOUS: gen/%/genesis.json

# devnet & testnet
NETWORKS = testnet devnet

gen/%/genesis.dump: gen/%/genesis.json
	./scripts/dump_genesis.sh $< > $@

gen/%/genesis.json: gen/%.json gen/generate.go
	$(GOPATH)/bin/genesis -n $(shell basename $(shell dirname $@)) -c $< -d $(subst .json,,$<)

gen: $(addsuffix gen, $(NETWORKS)) mainnetgen

$(addsuffix gen, $(NETWORKS)): %gen: gen/%/genesis.dump

# mainnet

gen/mainnet/genesis.dump: gen/mainnet/genesis.json
	./scripts/dump_genesis.sh gen/mainnet/genesis.json > gen/mainnet/genesis.dump

mainnetgen: gen/mainnet/genesis.dump

gen/mainnet/genesis.json: gen/pregen/mainnet/genesis.csv buildsrc
	mkdir -p gen/mainnet
	cat gen/pregen/mainnet/genesis.csv | $(GOPATH)/bin/incorporate -m gen/pregen/mainnet/metadata.json > gen/mainnet/genesis.json

capabilities: build
	sudo setcap cap_ipc_lock+ep ${GOPATH}/bin/kmd

dump: $(addprefix gen/,$(addsuffix /genesis.dump, $(NETWORKS)))

install: build
	scripts/dev_install.sh -p ${GOPATH}/bin

.PHONY: default fmt vet lint sanity cover prof deps build test fulltest shorttest clean cleango deploy node_exporter install %gen gen NONGO_BIN
