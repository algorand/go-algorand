#!/usr/bin/env bash
echo $(cat ./go.mod | grep 'go ' | head -n 1 | cut -d' ' -f2)
