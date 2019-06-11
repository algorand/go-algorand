#!/usr/bin/env bash

git branch -vv | grep 'origin/.*: gone]' | awk '{print }' | cut -d' ' -f 3 | xargs git branch -D
