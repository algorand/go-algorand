#!/usr/bin/env bash

export GOPATH=$(go env GOPATH)
cd ${GOPATH}/src/github.com/algorand/go-algorand/daemon/kmd/api

cat <<EOM | gofmt >../lib/kmdapi/bundledSpecInject.go
// Code generated during build process, along with swagger.json. DO NOT EDIT.
package kmdapi

func init() {
	SwaggerSpecJSON = string([]byte{
	$(cat swagger.json | hexdump -v -e '1/1 "0x%02X, "' | fmt)
	})
}

EOM
