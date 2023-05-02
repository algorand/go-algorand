#!/usr/bin/env bash

set -eo pipefail

# The following is intentional - hardcoding a token for public repos is recommended here to allow fork access
/usr/bin/env bash scripts/travis/codecov -t 8b4a1f91-f154-4c26-b84c-c9aaa90159c6
