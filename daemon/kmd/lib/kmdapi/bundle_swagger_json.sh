#!/usr/bin/env bash

THISDIR=$(dirname $0)

cat <<EOM | gofmt > $THISDIR/bundledSpecInject.go
// Code generated during build process, along with swagger.json. DO NOT EDIT.
package kmdapi

func init() {
	SwaggerSpecJSON = string([]byte{
	$(cat $THISDIR/../../api/swagger.json | hexdump -v -e '1/1 "0x%02X, "' | fmt)
	})
}

EOM
