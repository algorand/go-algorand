#!/bin/bash

set -e

# Need to log in to Docker desktop before docker push will succeed.
# e.g. `docker login`
# Log in account should be 'algorand'.

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
cd ${SCRIPTPATH}

docker build -f Dockerfile-testnet . -t algorand/testnet-telem:latest
docker push algorand/testnet-telem:latest
