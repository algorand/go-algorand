#!/usr/bin/env bash
echo $(awk '/^go[ \t]+[0-9]+\.[0-9]+(\.[0-9]+)?.*$/{print $2}' go.mod)
