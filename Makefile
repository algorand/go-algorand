GOPATH		:= $(shell go env GOPATH)
export GOPATH
UNAME		:= $(shell uname)
SRCPATH     := $(GOPATH)/src/github.com/algorand/go-algorand

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

SOURCES := $(shell cd $(SRCPATH) && \
		go list ./... | grep -v /go-algorand/test/)

UNIT_TEST_SOURCES := $(sort $(shell cd $(SRCPATH) && go list ./... | grep -v /go-algorand/test/ | grep -v /go-algorand/vendor/ ))
E2E_TEST_SOURCES := $(shell cd $(SRCPATH)/test/e2e-go && go list ./...)

default: build

# tools

fmt:
	cd $(SRCPATH) && \
		go fmt `go list ./... | grep -v /vendor/`

fix: build
	cd $(SRCPATH) && \
		$(GOPATH)/bin/algofix `ls -d */ | grep -vw vendor`

fixcheck: build
	cd $(SRCPATH) && \
		$(GOPATH)/bin/algofix -error `ls -d */ | grep -vw vendor`

lint: deps
	cd $(SRCPATH) && \
		$(GOPATH)/bin/golint `go list ./... | grep -v /vendor/`

depensure:
	cd $(SRCPATH) && \
		$(GOPATH)/bin/dep ensure

vet:
	cd $(SRCPATH) && \
		go vet `go list ./... | grep -v /vendor/`

sanity: vet fix lint fmt

cover:
	cd $(SRCPATH) && \
		go test $(GOTAGS) -coverprofile=cover.out $(UNIT_TEST_SOURCES)

prof:
	cd $(SRCPATH)/node && \
		go test $(GOTAGS) -cpuprofile=cpu.out -memprofile=mem.out -mutexprofile=mutex.out

generate: deps
	cd $(SRCPATH) && \
		PATH=$(GOPATH)/bin:$$PATH \
		go generate `go list ./... | grep -v /vendor/`

# build our fork of libsodium, placing artifacts into crypto/lib/ and crypto/include/
$(SRCPATH)/crypto/lib/libsodium.a:
	cd $(SRCPATH)/crypto/libsodium-fork && \
		./autogen.sh && \
		./configure --disable-shared --prefix="$(SRCPATH)/crypto/" && \
		$(MAKE) && \
		$(MAKE) install

deps:
	$(SRCPATH)/scripts/check_deps.sh

# artifacts

# Regenerate algod swagger spec files
ALGOD_API_SWAGGER_SPEC := $(SRCPATH)/daemon/algod/api/swagger.json
ALGOD_API_FILES := $(shell find $(SRCPATH)/daemon/algod/api/server/common -type f) \
	$(shell find $(SRCPATH)/daemon/algod/api/server/v1 -type f) \
	$(SRCPATH)/daemon/algod/api/server/router.go
ALGOD_API_SWAGGER_INJECT := $(SRCPATH)/daemon/algod/api/server/lib/bundledSpecInject.go

# Note that swagger.json requires the go-swagger dep.
$(ALGOD_API_SWAGGER_SPEC): $(ALGOD_API_FILES)
	$(info "regenerating swagger.json due to changes in algod/api/server")
	@cd $(SRCPATH)/daemon/algod/api && \
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
	$(SRCPATH)/daemon/algod/api/server/lib/bundle_swagger_json.sh

# Regenerate kmd swagger spec files
KMD_API_SWAGGER_SPEC := $(SRCPATH)/daemon/kmd/api/swagger.json
KMD_API_DIRS := $(shell find $(SRCPATH)/daemon/kmd/api/ -type d)
KMD_API_FILES := $(shell find $(SRCPATH)/daemon/kmd/api/ -type f | grep -v $(KMD_API_SWAGGER_SPEC))
KMD_API_SWAGGER_WRAPPER := kmdSwaggerWrappers.go
KMD_API_SWAGGER_INJECT := $(SRCPATH)/daemon/kmd/lib/kmdapi/bundledSpecInject.go

# Note that swagger.json requires the go-swagger dep.
$(KMD_API_SWAGGER_SPEC): $(KMD_API_DIRS) $(KMD_API_FILES)
	$(info "regenerating swagger.json due to changes in kmd")
	@cd $(SRCPATH)/daemon/kmd/lib/kmdapi && \
		python genSwaggerWrappers.py $(KMD_API_SWAGGER_WRAPPER) && \
		cd $(SRCPATH)/daemon/kmd && \
		PATH=$(GOPATH)/bin:$$PATH \
		go generate ./... && \
		rm $(SRCPATH)/daemon/kmd/lib/kmdapi/$(KMD_API_SWAGGER_WRAPPER)
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
	$(SRCPATH)/daemon/kmd/lib/kmdapi/bundle_swagger_json.sh

# develop

build: buildsrc gen

buildsrc: $(SRCPATH)/crypto/lib/libsodium.a node_exporter NONGO_BIN deps $(ALGOD_API_SWAGGER_INJECT) $(KMD_API_SWAGGER_INJECT)
	cd $(SRCPATH) && \
		go install $(GOTRIMPATH) $(GOTAGS) -ldflags="$(GOLDFLAGS)" $(SOURCES)
	cd $(SRCPATH) && \
		go vet $(UNIT_TEST_SOURCES) $(E2E_TEST_SOURCES)

SOURCES_RACE := github.com/algorand/go-algorand/cmd/kmd

## Build binaries with the race detector enabled in them.
## This allows us to run e2e tests with race detection.
## We overwrite bin-race/kmd with a non -race version due to
## the incredible performance impact of -race on Scrypt.
build-race: build
	@mkdir -p $(GOPATH)/bin-race
	cd $(SRCPATH) && \
		GOBIN=$(GOPATH)/bin-race go install $(GOTRIMPATH) $(GOTAGS) -race -ldflags="$(GOLDFLAGS)" $(SOURCES) && \
		GOBIN=$(GOPATH)/bin-race go install $(GOTRIMPATH) $(GOTAGS) -ldflags="$(GOLDFLAGS)" $(SOURCES_RACE)

NONGO_BIN_FILES=$(GOPATH)/bin/find-nodes.sh $(GOPATH)/bin/update.sh $(GOPATH)/bin/COPYING

NONGO_BIN: $(NONGO_BIN_FILES)

$(GOPATH)/bin/find-nodes.sh: scripts/find-nodes.sh

$(GOPATH)/bin/update.sh: cmd/updater/update.sh

$(GOPATH)/bin/COPYING: COPYING

$(GOPATH)/bin/%:
	cp -f $< $@

test: build
	cd $(SRCPATH) && \
		go test $(GOTAGS) -race $(UNIT_TEST_SOURCES)

fulltest: build-race
	cd $(SRCPATH) && for PACKAGE_DIRECTORY in $(UNIT_TEST_SOURCES) ; do \
		go test $(GOTAGS) -timeout 2000s -race $$PACKAGE_DIRECTORY; \
		done

shorttest: build-race $(addprefix short_test_target_, $(UNIT_TEST_SOURCES))

$(addprefix short_test_target_, $(UNIT_TEST_SOURCES)): build
	@cd $(SRCPATH) && \
	go test $(GOTAGS) -short -timeout 2000s -race $(subst short_test_target_,,$@)

integration: build-race
	cd $(SRCPATH) && \
		./test/scripts/run_integration_tests.sh

testall: fulltest integration

# generated files we should make sure we clean
GENERATED_FILES := $(SRCPATH)/daemon/algod/api/bundledSpecInject.go \
	$(SRCPATH)/daemon/algod/api/lib/bundledSpecInject.go \
	$(SRCPATH)/daemon/kmd/lib/kmdapi/bundledSpecInject.go

clean:
	cd $(SRCPATH) && \
		go clean -i ./...
	rm -f $(GOPATH)/bin/node_exporter
	rm -f $(GENERATED_FILES)
	cd crypto/libsodium-fork && \
		test ! -e Makefile || make clean
	rm -rf $(SRCPATH)/crypto/lib

# clean without crypto
cleango:
	cd $(SRCPATH) && \
		go clean -i ./...
	rm -f $(GOPATH)/bin/node_exporter
	rm -f $(GENERATED_FILES)

# assign the phony target node_exporter the dependency of the actual executable.
node_exporter: $(GOPATH)/bin/node_exporter

# The recipe for making the node_exporter is by extracting it from the gzipped&tar file.
# The file is was taken from the S3 cloud and it traditionally stored at
# /travis-build-artifacts-us-ea-1.algorand.network/algorand/node_exporter/latest/node_exporter-stable-linux-x86_64.tar.gz
$(GOPATH)/bin/node_exporter:
	cd $(GOPATH)/bin && \
		tar -xzvf $(SRCPATH)/installer/external/node_exporter-stable-$(shell ./scripts/ostype.sh)-$(shell uname -m | tr '[:upper:]' '[:lower:]').tar.gz

# deploy

deploy:
	cd $(SRCPATH) && \
		scripts/deploy_dev.sh

.PRECIOUS: gen/%/genesis.json

# devnet & testnet
NETWORKS = testnet devnet

gen/%/genesis.dump: gen/%/genesis.json
	cd $(SRCPATH) && \
		./scripts/dump_genesis.sh $< > $@

gen/%/genesis.json: gen/%.json $(SRCPATH)/gen/generate.go
	cd $(SRCPATH) && \
		$(GOPATH)/bin/genesis -n $(shell basename $(shell dirname $@)) -c $< -d $(subst $(SRCPATH)/,,$(subst .json,,$<))

gen: $(addsuffix gen, $(NETWORKS)) mainnetgen

$(addsuffix gen, $(NETWORKS)): %gen: gen/%/genesis.dump

# mainnet

$(SRCPATH)/gen/mainnet/genesis.dump: $(SRCPATH)/gen/mainnet/genesis.json
	cd $(SRCPATH) && \
		./scripts/dump_genesis.sh gen/mainnet/genesis.json > gen/mainnet/genesis.dump

mainnetgen: $(SRCPATH)/gen/mainnet/genesis.dump

$(SRCPATH)/gen/mainnet/genesis.json: $(SRCPATH)/gen/pregen/mainnet/genesis.csv buildsrc
	cd $(SRCPATH) && \
		mkdir -p gen/mainnet && \
		cat $(SRCPATH)/gen/pregen/mainnet/genesis.csv | $(GOPATH)/bin/incorporate -m $(SRCPATH)/gen/pregen/mainnet/metadata.json > $(SRCPATH)/gen/mainnet/genesis.json

capabilities: build
	sudo setcap cap_ipc_lock+ep ${GOPATH}/bin/kmd

dump: $(addprefix gen/,$(addsuffix /genesis.dump, $(NETWORKS)))

install: build
	cd $(SRCPATH) && \
		scripts/dev_install.sh -p ${GOPATH}/bin

.PHONY: default fmt vet lint sanity cover prof deps build test fulltest shorttest clean cleango deploy node_exporter install %gen gen NONGO_BIN
