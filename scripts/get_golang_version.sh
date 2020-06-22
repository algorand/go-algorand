#!/usr/bin/env bash
awk '/^go[ \t]+[0-9]+\.[0-9]+(\.[0-9]+)?[ \t]*$/{print $2}' go.mod
