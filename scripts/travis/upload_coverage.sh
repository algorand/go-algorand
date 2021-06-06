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

/usr/bin/env bash scripts/travis/codecov
