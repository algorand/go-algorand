#!/bin/bash

# build_prod.sh - Used to build production (Release) versions of our binaries.  This script ensures the build number
#           and current commit hash are baked into the algod binary.
#           Other production-time modifiers effected here.
#           To use the same build number across builds (since it's currently time-based),
#           set BUILDNUMBER in the environment.  Otherwise we will compute it inline.
#
# Syntax:   build_prod.sh
#
# Outputs:  <build output>
#
# ExitCode: 0 = Enlistment clean
#
# Usage:    Can be used at any time to build production binaries (with build version info).
#           Currently used by build_package.sh to generate production binaries for each platform.
#
# Examples: scripts/build_prod.sh

make build
