#!/usr/bin/env bash

set -eo pipefail

# if [[ -z "$CODECOV_TOKEN" ]]; then
#   /usr/bin/env bash scripts/travis/codecov
# else
#   /usr/bin/env bash scripts/travis/codecov -t $CODECOV_TOKEN
# fi

if [[ -z "$CIRCLE_SHA1" ]]; then
  /usr/bin/env bash scripts/travis/codecov
else
  echo "INFO: Using sha1 $CIRCLE_SHA1"
  /usr/bin/env bash scripts/travis/codecov -C $CIRCLE_SHA1
fi
