#!/usr/bin/env bash
go version 2>&1 | awk 'BEGIN {v=""}; /^go version go[0-9]+\.[0-9]+(\.[0-9]+)?[ \t]*.*$/{v=$3}; END {print(v)}' | sed 's/go//'
