#!/usr/bin/env bash
GOLANG_VERSION=$(awk '/^go/{print $2}' go.mod)
echo "${GOLANG_VERSION}"
