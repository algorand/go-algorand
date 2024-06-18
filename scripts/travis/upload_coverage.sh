#!/usr/bin/env bash

set -eo pipefail

if [[ -z "$CODECOV_TOKEN" ]]; then
  /usr/bin/env bash scripts/travis/codecov
else
  /usr/bin/env bash scripts/travis/codecov -t $CODECOV_TOKEN
fi
