#!/usr/bin/env bash

set -eo pipefail

if [[ -z "$CIRCLE_SHA1" ]]; then
  /usr/bin/env bash scripts/travis/codecov
else
  echo "INFO: Using sha1 $CIRCLE_SHA1"
  /usr/bin/env bash scripts/travis/codecov -C $CIRCLE_SHA1
fi
