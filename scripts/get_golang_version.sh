#!/usr/bin/env bash

# The "all" argument is used in the `./scripts/check_golang_version.sh` script
# and parsed as an array to check against the system's golang version depending
# upon the context in which the project is being built.
#
# "dev" is to be used to satisfy the minimum requirement we have to successfully
# build the project.
#
# The default is to return the pinned version needed for our production builds.
# Our build task-runner `mule` will refer to this script and will automatically
# build a new image whenever the version number has been changed.

BUILD=1.23.9
MIN=$(echo $BUILD | cut -d. -f1-2).0

if [ "$1" = all ]
then
    echo $BUILD $MIN
elif [ "$1" = dev ]
then
    echo $MIN
else
    echo $BUILD
fi

