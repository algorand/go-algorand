#!/usr/bin/env bash

if [[ "$1" =~ ^rel/ ]]; then
    echo "disable"
else
    echo "enable"
fi
