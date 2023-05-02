#!/usr/bin/env bash

# Print a warning when there is a new version notification before uploading the
# coverage report to codecov.
set -eo pipefail

# Check if there is a new version.
curl -fLso codecov https://codecov.io/bash
UPSTREAM_VERSION=$(grep -o 'VERSION=\"[0-9\.]*\"' codecov | cut -d'"' -f2)
LOCAL_VERSION=$(grep -o 'VERSION=\"[0-9\.]*\"' scripts/travis/codecov | cut -d'"' -f2)
if [[ "${UPSTREAM_VERSION}" != "${LOCAL_VERSION}" ]]; then
  echo "WARN: version ${UPSTREAM_VERSION} of the codecov upload script is available."
fi

# The following is intentional - hardcoding a token for public repos is recommended here to allow fork access
/usr/bin/env bash scripts/travis/codecov -t 8b4a1f91-f154-4c26-b84c-c9aaa90159c6
