#!/usr/bin/env bash

export GOPATH=$(go env GOPATH)
cd ${GOPATH}/src/github.com/algorand/go-algorand/daemon/algod/api

cat <<EOM | gofmt >./server/lib/bundledSpecInject.go
// Code generated during build process, along with swagger.json. DO NOT EDIT.
package lib

func init() {
	SwaggerSpecJSON = string([]byte{
	$(cat swagger.json | hexdump -v -e '1/1 "0x%02X, "' | fmt)
	})
}

EOM
