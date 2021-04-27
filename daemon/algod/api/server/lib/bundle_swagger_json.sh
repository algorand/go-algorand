#!/usr/bin/env bash

THISDIR=$(dirname $0)

LICENSE_LOCATION="$THISDIR"/../../../../../scripts/LICENSE_HEADER
LICENSE=$(sed "s/{DATE_Y}/$(date +"%Y")/" "$LICENSE_LOCATION")

printf "%s\n" "$LICENSE" > $THISDIR/bundledSpecInject.go
cat <<EOM | gofmt >> $THISDIR/bundledSpecInject.go
// Code generated during build process, along with swagger.json. DO NOT EDIT.
package lib

func init() {
	SwaggerSpecJSON = string([]byte{
	$(cat $THISDIR/../../swagger.json | hexdump -v -e '1/1 "0x%02X, "' | fmt)
	})
}

EOM
