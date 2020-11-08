# Package Build Pipeline

- [Environment Variables](#environment-variables)
- [Build Stages](#build-stages)
- [Custom Builds](#custom-builds)
- [Examples](#examples)
- [Manual Deploy](#manual-deploy)

# Environment Variables

Each stage listed in the next section will have several environment variables automatically that are available to the stage. Depending on the stage, the environment variables may be exported to subprocesses.

These env vars generally don't change between stages. Here is a list of variables that are computed if not passed on the CLI (more on that later):

- `ARCH_TYPE`, i.e., `amd64`
- `BRANCH`
- `CHANNEL`
- `OS_TYPE`
- `VERSION`

In addition, make sure that the following AWS credentials are set in environment variables:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

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
        + calls `ci-build` make target
        + packages `deb`, `rpm` and `docker`

    - package-deb
        + packages only `deb`

    - package-rpm:
        + packages only `rpm`

    - package-docker
        + packages docker image

## upload

- see `./go-algorand/package-upload.yaml`

- customizable environment variables:

    + `CHANNEL`
    + `STAGING`
    + `VERSION`

#### `mule` jobs

    - package-upload

## test

- see `./go-algorand/package-test.yaml`

- customizable environment variables:

    + `BRANCH`
    + `CHANNEL`
    + `ARCH_BIT`, i.e., the value from `uname -m`
    + `NETWORK`
    + `S3_SOURCE`, i.e., the S3 bucket from which to download
    + `SHA`, i.e., the value from `git rev-parse HEAD` if not passed on CLI
    + `VERSION`

#### `mule` jobs

    - package-test
        + tests both `deb` and `rpm`

    - package-test-deb
        + tests only `deb`

    - package-test-rpm
        + tests only `rpm`

## sign

- see `./go-algorand/package-sign.yaml`

- customizable environment variables:

    + `BRANCH`
    + `CHANNEL`
    + `ARCH_BIT`, i.e., the value from `uname -m`
    + `S3_SOURCE`, i.e., the S3 bucket from which to download
    + `VERSION`

### `mule` jobs

    - package-sign
        + signs all build artifacts

## deploy

- see `./go-algorand/package-deploy.yaml`

- customizable environment variables:

    + `CHANNEL`
    + `NETWORK`
    + `NO_DEPLOY`
    + `PACKAGES_DIR`
    + `S3_SOURCE`
    + `VERSION`

#### `mule` jobs

    - package-deploy-rpm
        + deploys `rpm`

    - docker-hub
        + pushes new image to docker hub

    - releases-page
        + creates and pushes new releases page to S3

# Custom Builds

It is sometimes necessary to create packages after doing a local build.

For example, the packaging build process will look like this:

```
mule -f package.yaml package
```

This can produce packages like the following:

```
algorand_dev_linux-amd64_2.1.86615.deb
algorand-devtools_dev_linux-amd64_2.1.86615.deb
```

Note that this is in the format `{ALGORAND_PACKAGE_NAME}_{CHANNEL}_{OS_TYPE}-{ARCH_TYPE}_{VERSION}.deb. `rpm` packages will follow their own format which is easy to intuit.

It is common that a custom build is performed on a feature branch other than `rel/stable` or `rel/beta` and that the build environment will need to be modified. In these instances, it is important to be able to pass values to the build process to customize a build.

The most common way to do this is to modify the environment that the subprocess inherits by specifying the values on the command *before* the command.  This won't need to be done for the package stage, but often needs to be done with subsequent stages.

In order to be able to correctly run some of the stages, such as testing and signing, several values needed by the subsequent stages must be explicitly passed to those stages.

> Verifying which env vars can be overridden is as simple as opening the `mule` yaml file for the respective stage and examining the list of env vars in the `agents`' `env` list.
>
>   For example:
>
>       agents:
>         - name: deb
>           dockerFilePath: docker/build/cicd.ubuntu.Dockerfile
>           image: algorand/mule-linux-debian
>           version: scripts/configure_dev-deps.sh
>           buildArgs:
>             - GOLANG_VERSION=`./scripts/get_golang_version.sh`
>           env:
>             - BRANCH=$BRANCH
>             - CHANNEL=$CHANNEL
>             - NETWORK=$NETWORK
>             - SHA=$SHA
>             - VERSION=$VERSION

Let's look at some examples.

# Examples

### Packaging

    mule -f package.yaml package

### Uploading

    STAGING=the-staging-area CHANNEL=beta VERSION=latest mule -f package-upload.yaml package-upload

### Testing

1. As part of the test suite, the `verify_package_string.sh` test needs the `BRANCH` as well as the `SHA`:

        BRANCH=update_signing CHANNEL=dev SHA=aecd5318 VERSION=2.1.86615 mule -f package-test.yaml package-test

1. To test local packages on the filesystem, do not set the `S3_SOURCE` environment variable. Note that the tests still expect the packages to be in the usual place, i.e., `./go-algorand/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE/`.

        BRANCH=update_signing CHANNEL=dev VERSION=2.1.86615 mule -f package-test.yaml package-test

1. By setting the `S3_SOURCE` variable, the script will know to download packages from staging (instead of getting them from the local filesystem) and test.  This will download the packages to the usual place, i.e., `./go-algorand/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE/`.

    Note that this can be used to test a pending official release.

        CHANNEL=beta S3_SOURCE=the-staging-area VERSION=2.1.6 mule -f package-test.yaml package-test

1. When testing locally, very often it is necessary to specify the `BRANCH`, `NETWORK` and `SHA` of the last commit to be able to having passing tests.  This is because the local environment will most likely not match the environment in which the packages were packaged.

        BRANCH=rel/stable CHANNEL=stable NETWORK=mainnet S3_SOURCE=the-staging-area SHA=df65da2b VERSION=2.1.6 mule -f package-test.yaml package-test

### Signing

1. Sign local packages located on the filesystem because `S3_SOURCE` is not set. Note that the packages should be in the usual place, i.e., `./go-algorand/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE/`.

        CHANNEL=dev VERSION=2.1.86615 mule -f package-sign.yaml package-sign

1. Download packages from staging and sign. Again, the script will know to download from S3 because the `S3_SOURCE` has been set.  This will download the packages to the usual place, i.e., `./go-algorand/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE/`.

        CHANNEL=beta S3_SOURCE=the-staging-area VERSION=2.1.6 mule -f package-sign.yaml package-sign

### Deploying

1. The new rpm packages will be downloaded from staging if the `S3_SOURCE` variable is set. Each package will then be pushed to `s3:algorand-releases:`.

        S3_SOURCE=the-staging-area VERSION=2.1.6 mule -f package-deploy.yaml package-deploy-rpm

1. Packages are not downloaded from staging but rather are copied from the location on the local filesystem specified by `PACKAGES_DIR` in the `mule` yaml file. Each package will then be pushed to `s3:algorand-releases:`.

        PACKAGES_DIR=/packages_location/foo VERSION=2.1.86615 mule -f package-deploy.yaml package-deploy-rpm

1. `NO_DEPLOY` is set to `true`. Instead of automatically pushing to `s3:algorand-releases:`, this will copy the `rpmrepo` directory that was created in the container to the `WORKDIR` in the host environment (the `WORKDIR` is set in the `mule` yaml file).

    This is handy when testing a deployment and not yet ready to deploy.

        NO_DEPLOY=true S3_SOURCE=the-staging-area VERSION=2.1.6 mule -f package-deploy.yaml package-deploy-rpm

# Manual Deploy

> Before any processes are run, make sure that the signing keys have been added to the `gpg-agent`. The `gpg_preset_passphrase.sh` helper script is provided just for this purpose.

Currently, it is still necessary to run two stages manually: sign and deploy. This is for several reasons, though principally because GPG signing of the build assets occurs in both stages.

The processes that make up both stages have been `mule-ified` as much as possible, and all but one can be run as a `mule` task (deploying deb packages, which are done in its own separate docker container).

### Signing

Usually, the packages are pulled down from S3 where the eks pipeline or the `mule` `package-upload` task had placed them. Issue the following command to download and sign them:

```
CHANNEL=stable S3_SOURCE=the-internal-area VERSION=2.1.6 mule -f package-sign.yaml package-sign
```

> These are downloaded to the usual location at `tmp/node_pkgs/OS_TYPE/ARCH/` on the local filesystem.

### Misc

The following is an example of several commands issued for all the stages when building locally:

```
mule -f package.yaml package
CHANNEL=dev VERSION=2.1.87522 SHA=730b3fd0 mule -f package-test.yaml package-test
CHANNEL=dev VERSION=2.1.87522 mule -f package-sign.yaml package-sign
CHANNEL=dev VERSION=2.1.87522 mule -f package-upload.yaml package-upload
CHANNEL=dev VERSION=2.1.87522 NO_DEPLOY=true mule -f package-deploy.yaml package-deploy
mule -f package-deploy.yaml releases-page

docker build --build-arg AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" --build-arg AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" -t aptly-test .

docker run --name aptly-algorand --rm -i -v "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent":/root/.gnupg/S.gpg-agent -v "$HOME/.gnupg/pubring.kbx":/root/.gnupg/pubring.kbx -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" -e CHANNEL=dev -e REPO=algorand -e VERSION=2.1.87522 aptly-test bash create_and_push

docker run --name aptly-algorand --rm -it aptly-test
```

