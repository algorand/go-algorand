#!/usr/bin/env bash

# Required GOLANG versions for project specified here.

BUILD=1.14.7
MIN=1.14
GO_MOD_SUPPORT=1.12

if [ "$1" = all ]
then
    echo $BUILD $MIN $GO_MOD_SUPPORT
elif [ "$1" = dev ]
then
    echo $MIN
else
    echo $BUILD
fi

