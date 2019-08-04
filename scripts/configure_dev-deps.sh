#!/usr/bin/env bash

set -x

GO111MODULE=off go get -u golang.org/x/lint/golint
GO111MODULE=off go get -u golang.org/x/tools/cmd/stringer
GO111MODULE=off go get -u github.com/go-swagger/go-swagger/cmd/swagger
