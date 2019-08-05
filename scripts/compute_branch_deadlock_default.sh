#!/usr/bin/env bash

# If enlistment isn't clean, it's 'dev'
./scripts/check_clean_enlistment.sh
if [[ $? -ne 0 ]]; then
    # dev / modified enlistment -- not production.  Enable deadlock detection
    echo "enable"
    exit 0
fi

if [[ "$1" =~ ^rel/ ]]; then
    echo "disable"
else
    echo "enable"
fi
