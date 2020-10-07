# Package Build Pipeline

- [Environment Variables](#environment-variables)
- [Build Stages](#build-stages)
- [Custom Builds](#custom-builds)
- [Examples](#examples)

# Environment Variables

Each stage listed in the next section will have several environment variables automatically that are available to the stage. Depending on the stage, the environment variables may be exported to subprocesses.

These env vars generally don't change between stages. Here is a list of variables that are computed if not passed on the CLI (more on that later):

- `ARCH_TYPE`, i.e., `amd64`
- `BRANCH`
- `CHANNEL`
- `OS_TYPE`
- `VERSION`

# Build Stages

- [package](#package)
- [upload](#upload)
- [test](#test)
- [sign](#sign)
- [deploy](#deploy)

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
- `PACKAGES_DIR`

#### `mule` jobs

    - package-deploy
        + deploys both `deb` and `rpm`

    - package-deploy-deb
        + deploys only `deb`

    - package-deploy-rpm
        + deploys only `rpm`

# Custom Builds

It is sometimes necessary to create packages after doing a local build.

For instance, it is common that a custom build is performed on a feature branch other than `rel/stable` or `rel/beta`.  Also, the version will need to be specified.  In these instances, it is important to be able to pass values to the build process to customize a build.

For example, the packaging build process would be starting as usual:

```
mule -f package.yaml package
```

This can produce packages like the following:

```
algorand_dev_linux-amd64_2.1.86615.deb
algorand-devtools_dev_linux-amd64_2.1.86615.deb
```

In order to be able to correctly run some of the stages, such as testing and signing, several values needed by the subsequent stages must to be explicitly passed to those stages.

Now, let's look at some examples.

# Examples

### Testing

1. As part of the test suite, the `verify_package_string.sh` test needs the `BRANCH` as well as the `SHA`:

```
BRANCH=update_signing CHANNEL=dev SHA=aecd5318 VERSION=2.1.86615 mule -f package-test.yaml package-test
```

2. Test local packages on the filesystem because `USE_CACHE` is set to `true`. Note that the tests still expect the packages to be in the usual place, i.e., `./go-algorand/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE/`.

As this is the default behavior, `USE_CACHE` can be omitted.

```
BRANCH=update_signing CHANNEL=dev USE_CACHE=true VERSION=2.1.86615 mule -f package-test.yaml package-test
```

3. Download packages from `s3:algorand-staging:` and test.  `USE_CACHE` is set to `false`. This will download the packages to the usual place, i.e., `./go-algorand/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE/`.

Note that this is used to test a pending official release.

```
CHANNEL=beta USE_CACHE=false VERSION=2.1.6 mule -f package-test.yaml package-test
```

### Testing

#1. Sign local packages on the filesystem because `USE_CACHE` is set to `true`. Note that the packages should be in the usual place, i.e., `./go-algorand/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE/`.
#
#As this is the default behavior, `USE_CACHE` can be omitted.
#
#```
#BRANCH=update_signing CHANNEL=dev USE_CACHE=true VERSION=2.1.86615 mule -f package-test.yaml package-test
#```

### Deploying

1. Packages will be automatically downloaded from `s3:algorand-staging`. Each package will then be pushed to `s3:algorand-releases:`.

```
VERSION=2.1.6 mule -f package-deploy.yaml package-deploy
```

2. Packages are not downloaded from `s3:algorand-staging` but rather are copied from the location on the local filesystem specified by `PACKAGES_DIR` in the `mule` yaml file. Each package will then be pushed to `s3:algorand-releases:`.

```
PACKAGES_DIR=/packages_location/foo VERSION=2.1.86615 mule -f package-deploy.yaml package-deploy
```

3. `NO_DEPLOY` is set to `true`. Instead of automatically pushing to `s3:algorand-releases:`, this will copy the `rpmrepo` directory that was created in the container to the `WORKDIR` in the host environment (the `WORKDIR` is set in the `mule` yaml file).

This is handy when testing a deployment and not yet ready to deploy.

```
NO_DEPLOY=true VERSION=2.1.6 mule -f package-deploy.yaml package-deploy
```

