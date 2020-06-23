#!/usr/bin/env bash
if go version > /dev/null 2>&1 ; then
   go version | awk '{print $3}' | sed 's/go//'
else
   echo ""
fi
