export GOPATH		:= $(shell go env GOPATH)
GOPATH1		:= $(firstword $(subst :, ,$(GOPATH)))
export GO111MODULE	:= on
export GOPROXY := https://gocenter.io

UNAME		:= $(shell uname)
SRCPATH     := $(shell pwd)
ARCH        := $(shell ./scripts/archtype.sh)
OS_TYPE     := $(shell ./scripts/ostype.sh)

# If build number already set, use it - to ensure same build number across multiple platforms being built
BUILDNUMBER      ?= $(shell ./scripts/compute_build_number.sh)
COMMITHASH       := $(shell ./scripts/compute_build_commit.sh)
BUILDBRANCH      ?= $(shell ./scripts/compute_branch.sh)
BUILDCHANNEL     ?= $(shell ./scripts/compute_branch_channel.sh $(BUILDBRANCH))
DEFAULTNETWORK   ?= $(shell ./scripts/compute_branch_network.sh $(BUILDBRANCH))
DEFAULT_DEADLOCK ?= $(shell ./scripts/compute_branch_deadlock_default.sh $(BUILDBRANCH))

GOTAGSLIST          := sqlite_unlock_notify sqlite_omit_load_extension

ifeq ($(UNAME), Linux)
EXTLDFLAGS := -static-libstdc++ -static-libgcc
ifeq ($(ARCH), amd64)
# the following predicate is abit misleading; it tests if we're not in centos.
ifeq (,$(wildcard /etc/centos-release))
EXTLDFLAGS  += -static
endif
GOTAGSLIST  += osusergo netgo static_build
GOBUILDMODE := -buildmode pie
endif
ifeq ($(ARCH), arm)
ifneq ("$(wildcard /etc/alpine-release)","")
EXTLDFLAGS  += -static
GOTAGSLIST  += osusergo netgo static_build
GOBUILDMODE := -buildmode pie
endif
endif
endif

GOTAGS      := --tags "$(GOTAGSLIST)"
GOTRIMPATH	:= $(shell go help build | grep -q .-trimpath && echo -trimpath)

GOLDFLAGS_BASE  := -X github.com/algorand/go-algorand/config.BuildNumber=$(BUILDNUMBER) \
		 -X github.com/algorand/go-algorand/config.CommitHash=$(COMMITHASH) \
		 -X github.com/algorand/go-algorand/config.Branch=$(BUILDBRANCH) \
		 -X github.com/algorand/go-algorand/config.DefaultDeadlock=$(DEFAULT_DEADLOCK) \
		 -extldflags \"$(EXTLDFLAGS)\"

GOLDFLAGS := $(GOLDFLAGS_BASE) \
		 -X github.com/algorand/go-algorand/config.Channel=$(BUILDCHANNEL)

UNIT_TEST_SOURCES := $(sort $(shell GO111MODULE=off go list ./... | grep -v /go-algorand/test/ ))
ALGOD_API_PACKAGES := $(sort $(shell GO111MODULE=off cd daemon/algod/api; go list ./... ))

MSGP_GENERATE	:= ./protocol ./crypto ./data/basics ./data/transactions ./data/committee ./data/bookkeeping ./data/hashable ./auction ./agreement ./rpcs ./node

default: build

# tools

fmt:
	go fmt ./...
	./scripts/check_license.sh -i

fix: build
	$(GOPATH1)/bin/algofix */

fixcheck: build
	$(GOPATH1)/bin/algofix -error */

lint: deps
	$(GOPATH1)/bin/golint ./...

vet:
	go vet ./...

check_shell:
	find . -type f -name "*.sh" -exec shellcheck {} +

sanity: vet fix lint fmt

cover:
	go test $(GOTAGS) -coverprofile=cover.out $(UNIT_TEST_SOURCES)

prof:
	cd node && go test $(GOTAGS) -cpuprofile=cpu.out -memprofile=mem.out -mutexprofile=mutex.out

generate: deps
	PATH=$(GOPATH1)/bin:$$PATH go generate ./...

msgp: $(patsubst %,%/msgp_gen.go,$(MSGP_GENERATE))

%/msgp_gen.go: deps ALWAYS
	$(GOPATH1)/bin/msgp -file ./$(@D) -o $@ -warnmask github.com/algorand/go-algorand
ALWAYS:

# build our fork of libsodium, placing artifacts into crypto/lib/ and crypto/include/
crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a:
	mkdir -p crypto/copies/$(OS_TYPE)/$(ARCH)
	cp -R crypto/libsodium-fork crypto/copies/$(OS_TYPE)/$(ARCH)/libsodium-fork
	cd crypto/copies/$(OS_TYPE)/$(ARCH)/libsodium-fork && \
		./autogen.sh --prefix $(SRCPATH)/crypto/libs/$(OS_TYPE)/$(ARCH) && \
		./configure --disable-shared --prefix="$(SRCPATH)/crypto/libs/$(OS_TYPE)/$(ARCH)" && \
		$(MAKE) && \
		$(MAKE) install

deps:
	./scripts/check_deps.sh

# artifacts

# Regenerate algod swagger spec files
ALGOD_API_SWAGGER_SPEC := daemon/algod/api/swagger.json
ALGOD_API_FILES := $(shell find daemon/algod/api/server/common daemon/algod/api/server/v1 daemon/algod/api/spec/v1 -type f) \
	daemon/algod/api/server/router.go
ALGOD_API_SWAGGER_INJECT := daemon/algod/api/server/lib/bundledSpecInject.go

# Note that swagger.json requires the go-swagger dep.
$(ALGOD_API_SWAGGER_SPEC): $(ALGOD_API_FILES) crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a
	cd daemon/algod/api && \
		PATH=$(GOPATH1)/bin:$$PATH \
		go generate ./...

$(ALGOD_API_SWAGGER_INJECT): $(ALGOD_API_SWAGGER_SPEC) $(ALGOD_API_SWAGGER_SPEC).validated
	./daemon/algod/api/server/lib/bundle_swagger_json.sh

# Regenerate kmd swagger spec files
KMD_API_SWAGGER_SPEC := daemon/kmd/api/swagger.json
KMD_API_FILES := $(shell find daemon/kmd/api/ -type f | grep -v $(KMD_API_SWAGGER_SPEC))
KMD_API_SWAGGER_WRAPPER := kmdSwaggerWrappers.go
KMD_API_SWAGGER_INJECT := daemon/kmd/lib/kmdapi/bundledSpecInject.go

$(KMD_API_SWAGGER_SPEC): $(KMD_API_FILES) crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a
	cd daemon/kmd/lib/kmdapi && \
		python genSwaggerWrappers.py $(KMD_API_SWAGGER_WRAPPER)
	cd daemon/kmd && \
		PATH=$(GOPATH1)/bin:$$PATH \
		go generate ./...
	rm daemon/kmd/lib/kmdapi/$(KMD_API_SWAGGER_WRAPPER)

%/swagger.json.validated: %/swagger.json
	@problem=$$(cat $< | jq -c '.definitions[].properties | select(. != null) | with_entries(select(.value.type=="array" and .value.items.format=="uint8")) | select(. != {}) | keys[]'); \
	if [ "$${problem}" != "" ]; then \
		echo "detected uint8 array in $<:\n$${problem}\nDid you mean to use \"type: string, format: byte\"?"; \
		echo "you will need to fix these swagger problems to allow build to proceed"; \
		exit 1; \
	else \
		touch $@; \
	fi

$(KMD_API_SWAGGER_INJECT): $(KMD_API_SWAGGER_SPEC) $(KMD_API_SWAGGER_SPEC).validated
	./daemon/kmd/lib/kmdapi/bundle_swagger_json.sh

# develop

build: buildsrc gen

buildsrc: crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a node_exporter NONGO_BIN deps $(ALGOD_API_SWAGGER_INJECT) $(KMD_API_SWAGGER_INJECT)
	go install $(GOTRIMPATH) $(GOTAGS) $(GOBUILDMODE) -ldflags="$(GOLDFLAGS)" ./...

SOURCES_RACE := github.com/algorand/go-algorand/cmd/kmd

## Build binaries with the race detector enabled in them.
## This allows us to run e2e tests with race detection.
## We overwrite bin-race/kmd with a non -race version due to
## the incredible performance impact of -race on Scrypt.
build-race: build
	@mkdir -p $(GOPATH1)/bin-race
	GOBIN=$(GOPATH1)/bin-race go install $(GOTRIMPATH) $(GOTAGS) -race -ldflags="$(GOLDFLAGS)" ./...
	GOBIN=$(GOPATH1)/bin-race go install $(GOTRIMPATH) $(GOTAGS) -ldflags="$(GOLDFLAGS)" $(SOURCES_RACE)
	go vet ./...

NONGO_BIN_FILES=$(GOPATH1)/bin/find-nodes.sh $(GOPATH1)/bin/update.sh $(GOPATH1)/bin/COPYING $(GOPATH1)/bin/ddconfig.sh

NONGO_BIN: $(NONGO_BIN_FILES)

$(GOPATH1)/bin/find-nodes.sh: scripts/find-nodes.sh

$(GOPATH1)/bin/update.sh: cmd/updater/update.sh

$(GOPATH1)/bin/COPYING: COPYING

$(GOPATH1)/bin/ddconfig.sh: scripts/ddconfig.sh

$(GOPATH1)/bin/%:
	cp -f $< $@

test: build
	go test $(GOTAGS) -race $(UNIT_TEST_SOURCES) -timeout 3600s

ci-test: ci-build
ifeq ($(ARCH), amd64)
	RACE=-race
else
	RACE=
endif
	for PACKAGE_DIRECTORY in $(UNIT_TEST_SOURCES) ; do \
		go test $(GOTAGS) -timeout 2000s $(RACE) $$PACKAGE_DIRECTORY; \
	done

fulltest: build-race
	for PACKAGE_DIRECTORY in $(UNIT_TEST_SOURCES) ; do \
		go test $(GOTAGS) -timeout 2000s -race $$PACKAGE_DIRECTORY; \
	done

shorttest: build-race $(addprefix short_test_target_, $(UNIT_TEST_SOURCES))

$(addprefix short_test_target_, $(UNIT_TEST_SOURCES)): build
	@go test $(GOTAGS) -short -timeout 2000s -race $(subst short_test_target_,,$@)

integration: build-race
	./test/scripts/run_integration_tests.sh

ci-integration:

ifeq ($(ARCH), amd64)
	export NODEBINDIR=$(SRCPATH)/tmp/node_pkgs/$(OS_TYPE)/$(ARCH)/dev/$(OS_TYPE)-$(ARCH)/bin && \
	export PATH=$(SRCPATH)/tmp/node_pkgs/$(OS_TYPE)/$(ARCH)/dev/$(OS_TYPE)-$(ARCH)/bin:$$PATH && \
	export PATH=$(SRCPATH)/tmp/node_pkgs/$(OS_TYPE)/$(ARCH)/dev/$(OS_TYPE)-$(ARCH)/test-utils:$$PATH && \
	export SRCROOT=$(SRCPATH) && \
	./test/scripts/e2e_go_tests.sh
else
	export NODEBINDIR=$(SRCPATH)/tmp/node_pkgs/$(OS_TYPE)/$(ARCH)/dev/$(OS_TYPE)-$(ARCH)/bin && \
	export PATH=$(SRCPATH)/tmp/node_pkgs/$(OS_TYPE)/$(ARCH)/dev/$(OS_TYPE)-$(ARCH)/bin:$$PATH && \
	export PATH=$(SRCPATH)/tmp/node_pkgs/$(OS_TYPE)/$(ARCH)/dev/$(OS_TYPE)-$(ARCH)/test-utils:$$PATH && \
	export SRCROOT=$(SRCPATH) && \
	./test/scripts/e2e_go_tests.sh -norace
endif


testall: fulltest integration

# generated files we should make sure we clean
GENERATED_FILES := daemon/algod/api/bundledSpecInject.go \
	daemon/algod/api/lib/bundledSpecInject.go \
	daemon/kmd/lib/kmdapi/bundledSpecInject.go \
	$(ALGOD_API_SWAGGER_SPEC) $(ALGOD_API_SWAGGER_SPEC).validated \
	$(KMD_API_SWAGGER_SPEC) $(KMD_API_SWAGGER_SPEC).validated

clean:
	go clean -i ./...
	rm -f $(GOPATH1)/bin/node_exporter
	rm -f $(GENERATED_FILES)
	cd crypto/libsodium-fork && \
		test ! -e Makefile || make clean
	rm -rf crypto/lib
	rm -rf crypto/libs
	rm -rf crypto/copies

# clean without crypto
cleango:
	go clean -i ./...
	rm -f $(GOPATH1)/bin/node_exporter
	rm -f $(GENERATED_FILES)

# assign the phony target node_exporter the dependency of the actual executable.
node_exporter: $(GOPATH1)/bin/node_exporter

# The recipe for making the node_exporter is by extracting it from the gzipped&tar file.
# The file is was taken from the S3 cloud and it traditionally stored at
# /travis-build-artifacts-us-ea-1.algorand.network/algorand/node_exporter/latest/node_exporter-stable-linux-x86_64.tar.gz
$(GOPATH1)/bin/node_exporter:
	tar -xzvf installer/external/node_exporter-stable-$(shell ./scripts/ostype.sh)-$(shell uname -m | tr '[:upper:]' '[:lower:]').tar.gz -C $(GOPATH1)/bin

# deploy

deploy:
	scripts/deploy_dev.sh

.PRECIOUS: gen/%/genesis.json

# devnet & testnet
NETWORKS = testnet devnet

gen/%/genesis.dump: gen/%/genesis.json
	./scripts/dump_genesis.sh $< > $@

gen/%/genesis.json: gen/%.json gen/generate.go buildsrc
	$(GOPATH1)/bin/genesis -q -n $(shell basename $(shell dirname $@)) -c $< -d $(subst .json,,$<)

gen: $(addsuffix gen, $(NETWORKS)) mainnetgen

$(addsuffix gen, $(NETWORKS)): %gen: gen/%/genesis.dump

# mainnet

gen/mainnet/genesis.dump: gen/mainnet/genesis.json
	./scripts/dump_genesis.sh gen/mainnet/genesis.json > gen/mainnet/genesis.dump

mainnetgen: gen/mainnet/genesis.dump

gen/mainnet/genesis.json: gen/pregen/mainnet/genesis.csv buildsrc
	mkdir -p gen/mainnet
	cat gen/pregen/mainnet/genesis.csv | $(GOPATH1)/bin/incorporate -m gen/pregen/mainnet/metadata.json > gen/mainnet/genesis.json

capabilities: build
	sudo setcap cap_ipc_lock+ep $(GOPATH1)/bin/kmd

dump: $(addprefix gen/,$(addsuffix /genesis.dump, $(NETWORKS)))

install: build
	scripts/dev_install.sh -p $(GOPATH1)/bin

.PHONY: default fmt vet lint check_shell sanity cover prof deps build test fulltest shorttest clean cleango deploy node_exporter install %gen gen NONGO_BIN

### TARGETS FOR CICD PROCESS

ci-deps:
	scripts/configure_dev-deps.sh && \
	scripts/check_deps.sh

ci-build: buildsrc gen
	mkdir -p $(SRCPATH)/tmp/node_pkgs/$(OS_TYPE)/$(ARCH) && \
	PKG_ROOT=$(SRCPATH)/tmp/node_pkgs/$(OS_TYPE)/$(ARCH) NO_BUILD=True VARIATIONS=$(OS_TYPE)/$(ARCH) scripts/build_packages.sh $(OS_TYPE)/$(ARCH)
