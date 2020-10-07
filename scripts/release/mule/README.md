# Package Build Pipeline

## Build Stages

- [package](#package)
- [upload](#upload)
- [test](#test)
- [sign](#sign)
- [deploy](#deploy)

## Environment Variables

Each stage will have several environment variables automatically that are available to the stage. Depending on the stage, the environment variables may be exported to subprocesses.

These env vars generally don't change between stages. Here is a list of variables that are computed if not passed on the CLI (more on that later):

- `ARCH_TYPE`, i.e., `amd64`
- `BRANCH`
- `CHANNEL`
- `OS_TYPE`
- `VERSION`

## package

- see `./go-algorand/package.yaml`

#### `mule` jobs

    - package
        + packages both `deb` and `rpm`

    - package-deb
        + packages only `deb`

    - package-rpm:
        + packages only `rpm`

    - package-docker
        + packages docker image

## upload

- see `./go-algorand/package-test.yaml`

#### `mule` jobs

    - package-upload

## test

- see `./go-algorand/package-test.yaml`

- `ARCH_BIT`, i.e., the value from `uname -m`
- `NETWORK`
- `SHA`, i.e., the value from `git rev-parse HEAD` if not passed on CLI
- `USE_CACHE`

#### `mule` jobs

    - package-test
        + tests both `deb` and `rpm`

    - package-test-deb
        + tests only `deb`

    - package-test-rpm
        + tests only `rpm`

## sign

- see `./$go-algorand/package-sign.yaml`

- `ARCH_BIT`, i.e., the value from `uname -m`
- `USE_CACHE`

### `mule` jobs

    - package-sign
        + signs both `deb` and `rpm`

## deploy

- see `./go-algorand/package-deploy.yaml`

- `NETWORK`
- `NO_DEPLOY`

#### `mule` jobs

    - package-deploy
        + deploys both `deb` and `rpm`

    - package-deploy-deb
        + deploys only `deb`

    - package-deploy-rpm
        + deploys only `rpm`

