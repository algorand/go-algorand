#!/usr/bin/env bash

set -x

cd / && go get -u golang.org/x/lint/golint
cd / && go get -u github.com/nomad-software/vend
cd / && go get -u golang.org/x/tools/cmd/stringer
cd / && go get -u github.com/go-swagger/go-swagger/cmd/swagger
