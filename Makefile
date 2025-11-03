UNAME := $(shell uname)
ifneq (,$(findstring MINGW,$(UNAME)))
#Gopath is not saved across sessions, probably existing Windows env vars, override them
export GOPATH := $(HOME)/go
GOPATH1 := $(GOPATH)
export PATH := $(PATH):$(GOPATH)/bin
else
export GOPATH := $(shell go env GOPATH)
GOPATH1 := $(firstword $(subst :, ,$(GOPATH)))
endif
GOBIN := $(if $(shell go env GOBIN),$(shell go env GOBIN),$(GOPATH1)/bin)
SRCPATH     := $(shell pwd)
ARCH        := $(shell ./scripts/archtype.sh)
OS_TYPE     := $(shell ./scripts/ostype.sh)
# overrides for cross-compiling platform-specific binaries
ifdef CROSS_COMPILE_ARCH
  ARCH := $(CROSS_COMPILE_ARCH)
  GO_INSTALL := CGO_ENABLED=1 GOOS=$(OS_TYPE) GOARCH=$(ARCH) go build -o $(GOBIN)
else
  GO_INSTALL := go install
endif
S3_RELEASE_BUCKET = $$S3_RELEASE_BUCKET

GOLANG_VERSIONS            := $(shell ./scripts/get_golang_version.sh all)
GOLANG_VERSION_BUILD       := $(firstword $(GOLANG_VERSIONS))
GOLANG_VERSION_BUILD_MAJOR := $(shell echo $(GOLANG_VERSION_BUILD) | cut -d'.' -f1,2)
GOLANG_VERSION_MIN         := $(lastword $(GOLANG_VERSIONS))
GOLANG_VERSION_SUPPORT     := $(shell echo $(GOLANG_VERSION_MIN) | cut -d'.' -f1,2)
CURRENT_GO_VERSION         := $(shell go version | cut -d " " -f 3 | tr -d 'go')
CURRENT_GO_VERSION_MAJOR   := $(shell echo $(CURRENT_GO_VERSION) | cut -d'.' -f1,2)

# If build number already set, use it - to ensure same build number across multiple platforms being built
BUILDNUMBER      ?= $(shell ./scripts/compute_build_number.sh)
FULLBUILDNUMBER  ?= $(shell ./scripts/compute_build_number.sh -f)
COMMITHASH       := $(shell ./scripts/compute_build_commit.sh)
BUILDBRANCH      := $(shell ./scripts/compute_branch.sh)
CHANNEL          ?= $(shell ./scripts/compute_branch_channel.sh $(BUILDBRANCH))
DEFAULTNETWORK   ?= $(shell ./scripts/compute_branch_network.sh $(BUILDBRANCH))
DEFAULT_DEADLOCK ?= $(shell ./scripts/compute_branch_deadlock_default.sh $(BUILDBRANCH))

GOTAGSLIST          := sqlite_unlock_notify sqlite_omit_load_extension

# e.g. make GOTAGSCUSTOM=msgtrace
GOTAGSLIST += ${GOTAGSCUSTOM}

# If available, use gotestsum instead of 'go test'.
ifeq (, $(shell which gotestsum))
export GOTESTCOMMAND=go test
else
export GOTESTCOMMAND=gotestsum --format pkgname --jsonfile testresults.json --
endif

ifeq ($(OS_TYPE), darwin)
# M1 Mac--homebrew install location in /opt/homebrew
ifeq ($(ARCH), arm64)
export CPATH=/opt/homebrew/include
export LIBRARY_PATH=/opt/homebrew/lib
endif
endif

ifeq ($(UNAME), Linux)
EXTLDFLAGS := -static-libstdc++ -static-libgcc
# the following predicate is abit misleading; it tests if we're not in centos.
ifeq (,$(wildcard /etc/centos-release))
EXTLDFLAGS  += -static
endif
GOTAGSLIST  += osusergo netgo static_build
GOBUILDMODE := -buildmode pie
endif

ifneq (, $(findstring MINGW,$(UNAME)))
EXTLDFLAGS := -static -static-libstdc++ -static-libgcc
export GOBUILDMODE := -buildmode=exe
endif

ifeq ($(SHORT_PART_PERIOD), 1)
export SHORT_PART_PERIOD_FLAG := -s
endif

GOTAGS      := --tags "$(GOTAGSLIST)"

GOLDFLAGS_BASE  := -X github.com/algorand/go-algorand/config.BuildNumber=$(BUILDNUMBER) \
		 -X github.com/algorand/go-algorand/config.CommitHash=$(COMMITHASH) \
		 -X github.com/algorand/go-algorand/config.Branch=$(BUILDBRANCH) \
		 -X github.com/algorand/go-algorand/config.DefaultDeadlock=$(DEFAULT_DEADLOCK) \
		 -extldflags \"$(EXTLDFLAGS)\"

GOLDFLAGS := $(GOLDFLAGS_BASE) \
		 -X github.com/algorand/go-algorand/config.Channel=$(CHANNEL)

UNIT_TEST_SOURCES := $(sort $(shell GOPATH=$(GOPATH) && GO111MODULE=off && go list ./... | grep -v /go-algorand/test/ ))
ALGOD_API_PACKAGES := $(sort $(shell GOPATH=$(GOPATH) && GO111MODULE=off && cd daemon/algod/api; go list ./... ))

GOMOD_DIRS := ./tools/block-generator ./tools/x-repo-types

MSGP_GENERATE	:= ./protocol ./protocol/test ./crypto ./crypto/merklearray ./crypto/merklesignature ./crypto/stateproof ./data/basics ./data/transactions ./data/stateproofmsg ./data/committee ./data/bookkeeping ./data/hashable ./agreement ./rpcs ./network ./node ./ledger ./ledger/ledgercore ./ledger/store/trackerdb ./ledger/store/trackerdb/generickv ./ledger/encoded ./stateproof ./data/account ./daemon/algod/api/spec/v2

default: build

# tools

fmt:
	go fmt ./...
	./scripts/check_license.sh -i

fix: build
	$(GOBIN)/algofix */

modernize:
	GOTOOLCHAIN=auto go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest -any=false -bloop=false -rangeint=false -fmtappendf=false -waitgroup=false -stringsbuilder=false -omitzero=false -fix ./...

lint: deps
	$(GOBIN)/golangci-lint run -c .golangci.yml

expectlint:
	cd test/e2e-go/cli/goal/expect && python3 expect_linter.py *.exp

check_go_version:
	@if [ $(CURRENT_GO_VERSION_MAJOR) != $(GOLANG_VERSION_BUILD_MAJOR) ]; then \
		echo "Wrong major version of Go installed ($(CURRENT_GO_VERSION_MAJOR)). Please use $(GOLANG_VERSION_BUILD_MAJOR)"; \
		exit 1; \
	fi

tidy: check_go_version
	@echo "Tidying go-algorand"
	go mod tidy -compat=$(GOLANG_VERSION_SUPPORT)
	@for dir in $(GOMOD_DIRS); do \
		echo "Tidying $$dir" && \
		(cd $$dir && go mod tidy -compat=$(GOLANG_VERSION_SUPPORT)); \
	done

check_shell:
	find . -type f -name "*.sh" -exec shellcheck {} +

sanity: fix lint fmt tidy modernize

cover:
	go test $(GOTAGS) -coverprofile=cover.out $(UNIT_TEST_SOURCES)

prof:
	cd node && go test $(GOTAGS) -cpuprofile=cpu.out -memprofile=mem.out -mutexprofile=mutex.out

generate: deps
	PATH=$(GOBIN):$$PATH go generate ./...

msgp: $(patsubst %,%/msgp_gen.go,$(MSGP_GENERATE))

api:
	make -C daemon/algod/api

logic:
	make -C data/transactions/logic


%/msgp_gen.go: deps ALWAYS
		@set +e; \
		printf "msgp: $(@D)..."; \
		$(GOBIN)/msgp -file ./$(@D) -o $@ -warnmask github.com/algorand/go-algorand > ./$@.out 2>&1; \
		if [ "$$?" != "0" ]; then \
			printf "failed:\n$(GOBIN)/msgp -file ./$(@D) -o $@ -warnmask github.com/algorand/go-algorand\n"; \
			cat ./$@.out; \
			rm ./$@.out; \
			exit 1; \
		else \
			echo " done."; \
		fi; \
		rm -f ./$@.out
ALWAYS:

# build our fork of libsodium, placing artifacts into crypto/lib/ and crypto/include/
libsodium: crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a

crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a:
	mkdir -p crypto/copies/$(OS_TYPE)/$(ARCH)
	cp -R crypto/libsodium-fork/. crypto/copies/$(OS_TYPE)/$(ARCH)/libsodium-fork
	cd crypto/copies/$(OS_TYPE)/$(ARCH)/libsodium-fork && \
		./autogen.sh --prefix $(SRCPATH)/crypto/libs/$(OS_TYPE)/$(ARCH) && \
		./configure --disable-shared --prefix="$(SRCPATH)/crypto/libs/$(OS_TYPE)/$(ARCH)" $(EXTRA_CONFIGURE_FLAGS) && \
		$(MAKE) && \
		$(MAKE) install

universal:
ifeq ($(OS_TYPE),darwin)
	# build amd64 Mac binaries
	mkdir -p $(GOBIN)-darwin-amd64
	CROSS_COMPILE_ARCH=amd64 GOBIN=$(GOBIN)-darwin-amd64 MACOSX_DEPLOYMENT_TARGET=13.0 EXTRA_CONFIGURE_FLAGS='CFLAGS="-arch x86_64 -mmacos-version-min=13.0" --host=x86_64-apple-darwin' $(MAKE)

	# build arm64 Mac binaries
	mkdir -p $(GOBIN)-darwin-arm64
	CROSS_COMPILE_ARCH=arm64 GOBIN=$(GOBIN)-darwin-arm64 MACOSX_DEPLOYMENT_TARGET=13.0 EXTRA_CONFIGURE_FLAGS='CFLAGS="-arch arm64 -mmacos-version-min=13.0" --host=aarch64-apple-darwin' $(MAKE)

	# same for buildsrc-special
	cd tools/block-generator && \
	CROSS_COMPILE_ARCH=amd64 GOBIN=$(GOBIN)-darwin-amd64 MACOSX_DEPLOYMENT_TARGET=13.0 EXTRA_CONFIGURE_FLAGS='CFLAGS="-arch x86_64 -mmacos-version-min=13.0" --host=x86_64-apple-darwin' $(MAKE)
	CROSS_COMPILE_ARCH=arm64 GOBIN=$(GOBIN)-darwin-arm64 MACOSX_DEPLOYMENT_TARGET=13.0 EXTRA_CONFIGURE_FLAGS='CFLAGS="-arch arm64 -mmacos-version-min=13.0" --host=aarch64-apple-darwin' $(MAKE)

	# lipo together
	mkdir -p $(GOBIN)
	for binary in $$(ls $(GOBIN)-darwin-arm64); do \
		skip=false; \
		for nongo_file in $(NONGO_BIN_FILES) $(GOBIN)/node_exporter; do \
			if [ "$(GOBIN)/$$binary" = "$$nongo_file" ]; then \
				echo "Skipping non-binary file: $$binary"; \
				skip=true; \
				break; \
			fi; \
		done; \
		if [ "$$skip" = "true" ]; then \
			continue; \
		fi; \
		if [ -f $(GOBIN)-darwin-amd64/$$binary ]; then \
			lipo -create -output $(GOBIN)/$$binary \
			$(GOBIN)-darwin-arm64/$$binary \
			$(GOBIN)-darwin-amd64/$$binary; \
		else \
			echo "Warning: Binary $$binary exists in arm64 but not in amd64"; \
		fi; \
	done
	# copy NONGO_BIN files
	for nongo_file in $(NONGO_BIN_FILES); do \
		short_name=$$(basename $$nongo_file); \
		if [ -f $(GOBIN)-darwin-arm64/$$short_name ]; then \
			cp -f $(GOBIN)-darwin-arm64/$$short_name $$nongo_file; \
		else \
			echo "Warning: NONGO_BIN file $$short_name does not exist in arm64"; \
		fi; \
	done
	# for node_exporter cross-compilation is using universal binary already
	cp -f $(GOBIN)-darwin-arm64/node_exporter $(GOBIN)/node_exporter
else
	echo "OS_TYPE must be darwin for universal builds, skipping"
endif

deps:
	./scripts/check_deps.sh

# artifacts

# Regenerate kmd swagger spec files
KMD_API_SWAGGER_SPEC := daemon/kmd/api/swagger.json
KMD_API_FILES := $(shell find daemon/kmd/api/ -type f | grep -v $(KMD_API_SWAGGER_SPEC))
KMD_API_SWAGGER_WRAPPER := kmdSwaggerWrappers.go
KMD_API_SWAGGER_INJECT := daemon/kmd/lib/kmdapi/bundledSpecInject.go

$(KMD_API_SWAGGER_SPEC): $(KMD_API_FILES) crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a
	cd daemon/kmd/lib/kmdapi && \
		python3 genSwaggerWrappers.py $(KMD_API_SWAGGER_WRAPPER)
	cd daemon/kmd && \
		PATH=$(GOBIN):$$PATH \
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

$(KMD_API_SWAGGER_INJECT): deps $(KMD_API_SWAGGER_SPEC) $(KMD_API_SWAGGER_SPEC).validated
	./daemon/kmd/lib/kmdapi/bundle_swagger_json.sh

# generated files we should make sure we clean
GENERATED_FILES := \
	$(KMD_API_SWAGGER_INJECT) \
	$(KMD_API_SWAGGER_SPEC) $(KMD_API_SWAGGER_SPEC).validated

rebuild_kmd_swagger: deps
	rm -f $(GENERATED_FILES)
	# we need to invoke the make here since we want to ensure that the deletion and re-creating are sequential
	make $(KMD_API_SWAGGER_INJECT)

# develop

build: buildsrc buildsrc-special


buildsrc: check-go-version crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a node_exporter NONGO_BIN
	$(GO_INSTALL) -trimpath $(GOTAGS) $(GOBUILDMODE) -ldflags="$(GOLDFLAGS)" ./...

buildsrc-special:
	cd tools/block-generator && \
	$(GO_INSTALL) -trimpath $(GOTAGS) $(GOBUILDMODE) -ldflags="$(GOLDFLAGS)" ./...

check-go-version:
	./scripts/check_golang_version.sh build

## Build binaries with the race detector enabled in them.
## This allows us to run e2e tests with race detection.
## We overwrite bin-race/kmd with a non -race version due to
## the incredible performance impact of -race on Scrypt.
build-race: build
	@mkdir -p $(GOBIN)-race
	GOBIN=$(GOBIN)-race go install -trimpath $(GOTAGS) -race -ldflags="$(GOLDFLAGS)" ./...
	cp $(GOBIN)/kmd $(GOBIN)-race

# Build binaries needed for e2e/integration tests
build-e2e: check-go-version crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a
	@mkdir -p $(GOBIN)-race
	# Build regular binaries (kmd, algod, goal) and race binaries in parallel
	$(GO_INSTALL) -trimpath $(GOTAGS) $(GOBUILDMODE) -ldflags="$(GOLDFLAGS)" ./cmd/kmd ./cmd/algod ./cmd/goal & \
	GOBIN=$(GOBIN)-race go install -trimpath $(GOTAGS) -race -ldflags="$(GOLDFLAGS)" ./cmd/goal ./cmd/algod ./cmd/algoh ./cmd/tealdbg ./cmd/msgpacktool ./cmd/algokey ./cmd/pingpong ./tools/teal/algotmpl ./test/e2e-go/cli/tealdbg/cdtmock & \
	wait
	cp $(GOBIN)/kmd $(GOBIN)-race

NONGO_BIN_FILES=$(GOBIN)/find-nodes.sh $(GOBIN)/update.sh $(GOBIN)/COPYING $(GOBIN)/ddconfig.sh

NONGO_BIN: $(NONGO_BIN_FILES)

$(GOBIN)/find-nodes.sh: scripts/find-nodes.sh

$(GOBIN)/update.sh: cmd/updater/update.sh

$(GOBIN)/COPYING: COPYING

$(GOBIN)/ddconfig.sh: scripts/ddconfig.sh

$(GOBIN)/%:
	cp -f $< $@

test: build
	$(GOTESTCOMMAND) $(GOTAGS) -race $(UNIT_TEST_SOURCES) -timeout 1h -coverprofile=coverage.txt -covermode=atomic

testc:
	echo $(UNIT_TEST_SOURCES) | xargs -P8 -n1 go test -c

benchcheck: build
	$(GOTESTCOMMAND) $(GOTAGS) -race $(UNIT_TEST_SOURCES) -run ^NOTHING -bench Benchmark -benchtime 1x -timeout 1h

fulltest: build-race
	$(GOTESTCOMMAND) $(GOTAGS) -race $(UNIT_TEST_SOURCES) -timeout 1h -coverprofile=coverage.txt -covermode=atomic

shorttest: build-race
	$(GOTESTCOMMAND) $(GOTAGS) -short -race $(UNIT_TEST_SOURCES) -timeout 1h -coverprofile=coverage.txt -covermode=atomic

integration: build-race
	./test/scripts/run_integration_tests.sh

testall: fulltest integration

clean:
	go clean -i ./...
	rm -f $(GOBIN)/node_exporter
	cd crypto/libsodium-fork && \
		test ! -e Makefile || make clean
	rm -rf crypto/lib
	rm -rf crypto/libs
	rm -rf crypto/copies
	rm -rf ./gen/devnet ./gen/mainnetnet ./gen/testnet
	rm -rf $(GOBIN)-darwin-amd64 $(GOBIN)-darwin-arm64

# clean without crypto
cleango:
	go clean -i ./...
	rm -f $(GOBIN)/node_exporter

# assign the phony target node_exporter the dependency of the actual executable.
node_exporter: $(GOBIN)/node_exporter

# The recipe for making the node_exporter is by extracting it from the gzipped&tar file.
# The file is was taken from the S3 cloud and it traditionally stored at
# /travis-build-artifacts-us-ea-1.algorand.network/algorand/node_exporter/latest/node_exporter-stable-linux-x86_64.tar.gz
$(GOBIN)/node_exporter:
	mkdir -p $(GOBIN) && \
	cd $(GOBIN) && \
	if [ -z "$(CROSS_COMPILE_ARCH)" ]; then \
		tar -xzvf $(SRCPATH)/installer/external/node_exporter-stable-$(shell ./scripts/ostype.sh)-$(shell uname -m | tr '[:upper:]' '[:lower:]').tar.gz; \
	else \
		tar -xzvf $(SRCPATH)/installer/external/node_exporter-stable-$(shell ./scripts/ostype.sh)-universal.tar.gz; \
	fi && \
	cd -

# deploy

deploy:
	scripts/deploy_dev.sh

.PRECIOUS: gen/%/genesis.json

# devnet & testnet
NETWORKS = testnet devnet

gen/%/genesis.dump: gen/%/genesis.json
	./scripts/dump_genesis.sh $< > $@

gen/%/genesis.json: gen/%.json gen/generate.go buildsrc
	$(GOBIN)/genesis -q $(SHORT_PART_PERIOD_FLAG) -n $(shell basename $(shell dirname $@)) -c $< -d $(subst .json,,$<)

gen: $(addsuffix gen, $(NETWORKS)) mainnetgen

$(addsuffix gen, $(NETWORKS)): %gen: gen/%/genesis.dump

# mainnet

gen/mainnet/genesis.dump: gen/mainnet/genesis.json
	./scripts/dump_genesis.sh gen/mainnet/genesis.json > gen/mainnet/genesis.dump

mainnetgen: gen/mainnet/genesis.dump

# The mainnet genesis.json file generated by this target does not have timestamp value so the hash is different from the deployed mainnet,
# use a real genesis.json file from installer/genesis/mainnet/genesis.json if needed.
# This target is preserved as part of the history on how mainnet genesis.json was generated from the CSV file.
gen/mainnet/genesis.json: gen/pregen/mainnet/genesis.csv buildsrc
	mkdir -p gen/mainnet
	cat gen/pregen/mainnet/genesis.csv | $(GOBIN)/incorporate -m gen/pregen/mainnet/metadata.json > gen/mainnet/genesis.json

capabilities: build
	sudo setcap cap_ipc_lock+ep $(GOBIN)/kmd

dump: $(addprefix gen/,$(addsuffix /genesis.dump, $(NETWORKS)))

install: build
	scripts/dev_install.sh -p $(GOBIN)

.PHONY: default fmt lint check_shell sanity cover prof deps build build-race build-e2e test fulltest shorttest clean cleango deploy node_exporter install %gen gen NONGO_BIN check-go-version rebuild_kmd_swagger universal libsodium modernize

###### TARGETS FOR CICD PROCESS ######
include ./scripts/release/mule/Makefile.mule

archive:
	aws s3 cp tmp/node_pkgs s3://algorand-internal/channel/$(CHANNEL)/$(FULLBUILDNUMBER) --recursive --exclude "*" --include "*$(FULLBUILDNUMBER)*"

build_custom_linters:
	golangci-lint custom -v
	./custom-golangci-lint --version
