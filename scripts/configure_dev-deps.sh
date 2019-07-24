#!/usr/bin/env bash

set -x

go get -u golang.org/x/lint/golint
go get -u github.com/nomad-software/vend
go get -u golang.org/x/tools/cmd/stringer
