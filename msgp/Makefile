
# NOTE: This Makefile is only necessary if you 
# plan on developing the msgp tool and library.
# Installation can still be performed with a
# normal `go install`.

# generated unit test files
MGEN = ./msgp/defgen_test.go

SHELL := /bin/bash

BIN = $(GOBIN)/msgp

.PHONY: clean wipe install get-deps bench all

$(BIN): */*.go
	@go install ./...

install: $(BIN)

$(MGEN): ./msgp/defs_test.go
	go generate ./msgp

test: all
	go test -covermode=atomic -coverprofile=cover.out ./...

bench: all
	go test -bench ./...

clean:
	$(RM) $(MGEN)

wipe: clean
	$(RM) $(BIN)

get-deps:
	go get -d -t ./...

all: install $(MGEN)

# travis CI enters here
travis:
	go get -d -t ./...
	go build -o "$${GOPATH%%:*}/bin/msgp" .
	go generate ./msgp
	go generate ./_generated
	go test -v ./... ./_generated
