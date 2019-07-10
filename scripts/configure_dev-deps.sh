#!/usr/bin/env bash

set -x

go get -u golang.org/x/lint/golint
go get -u github.com/golang/dep/cmd/dep
go get -u golang.org/x/tools/cmd/stringer
