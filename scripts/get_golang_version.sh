#!/usr/bin/env bash
GOLANG_VERSION=$(grep 'go ' ./go.mod | head -n 1 | cut -d' ' -f2)
echo "${GOLANG_VERSION}"
