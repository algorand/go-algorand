# Algod Container

[![DockerHub](https://img.shields.io/badge/DockerHub-blue)](https://hub.docker.com/r/algorand/algod)

General purpose algod container image.

## Image Configuration

Algorand maintains a Docker image with recent snapshot builds from our `master` branch on DockerHub to support users who prefer to run containerized processes. There are a couple of different images available for running the latest stable or development versions of Algod.

- `algorand/algod:latest` is the latest stable release version of Algod (default)
- `algorand/algod:stable` is the latest stable version of Algod
- `algorand/algod:{version}-stable` is the stable version of Algod at a specific version number
- `algorand/algod:beta` is the version of Algod being considered for the next stable release
- `algorand/algod:nightly` is the latest development version of Algod

Algorand also publishes experimental versions of Algod.

- `algorand/algod:{LONGSHA}` is a version containing a specific commit to `master`
- `algorand/algod:master` is the version running on our `master` branch
- `algorand/algod:feature-{branch}` is the latest version of Algod on any of the go-algorand feature branches

Furthermore, There are a number of special files and environment variables used to control how a container is started. See below for more detail.

### Default Configuration

The following config.json overrides are applied:

| Setting | Value | Description |
| ------- | ----- | ----------- |
| EndpointAddress | 0.0.0.0:8080 | Ensure the API is accessible from outside of the container. |

### Environment Variables

The following environment variables can be supplied. Except when noted, it is possible to reconfigure deployments even after the data directory has been initialized.

| Variable | Description |
| -------- | ----------- |
| NETWORK         | Leave blank for a private network, otherwise specify one of mainnet, betanet, testnet, or devnet. Only used during a data directory initialization. |
| PROFILE         | If set, initializes the config.json file according to the given profile. |
| DEV_MODE        | If set to 1 on a private network, enable dev mode. Only used during data directory initialization.                                                  |
| START_KMD       | When set to 1, start kmd service with no timeout. THIS SHOULD NOT BE USED IN PRODUCTION.                                                            |
| FAST_CATCHUP    | If set to 1 on a public network, attempt to start fast-catchup during initial config.                                                               |
| TOKEN           | If set, overrides the REST API token.                                                                                                               |
| ADMIN_TOKEN     | If set, overrides the REST API admin token.                                                                                                         |
| KMD_TOKEN       | If set along with `START_KMD`, override the KMD REST API token.                                                                                     |
| TELEMETRY_NAME  | If set on a public network, telemetry is reported with this name.                                                                                   |
| NUM_ROUNDS      | If set on a private network, override default of 30000 participation keys.                                                                          |
| GENESIS_ADDRESS | If set, use this API address to initialize the genesis file. |
| PEER_ADDRESS    | If set, override phonebook with peer ip:port (or semicolon separated list: ip:port;ip:port;ip:port...)                                              |
| GOSSIP_PORT     | If set, configure the node to listen for external connections on this address. For example "4161" |

### Special Files

Configuration can be modified by specifying certain files. These can be changed each time you start the container if the data directory is a mounted volume.

| File | Description |
| ---- | ----------- |
| /etc/algorand/config.json | Override default configurations by providing your own file. |
| /etc/algorand/algod.token | Override default randomized REST API token. |
| /etc/algorand/algod.admin.token | Override default randomized REST API admin token. |
| /etc/algorand/logging.config | Use a custom [logging.config](https://developer.algorand.org/docs/run-a-node/reference/telemetry-config/#configuration) file for configuring telemetry. |
| /etc/algorand/template.json | Override default private network topology. One of the nodes in the template must be named "data". |
| /etc/algorand/keys/ | Override this directory to provide pregenerated private network data. |

## Example Configuration

The following command launches a container configured with one of the public networks:

```bash
docker run --rm -it \
    -p 4190:8080 \
    -p 4191:7833 \
    -e NETWORK=mainnet \
    -e FAST_CATCHUP=1 \
    -e TELEMETRY_NAME=name \
    -e TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    -e START_KMD=1 \
    -v ${PWD}/data:/algod/data/ \
    --name mainnet-container \
    algorand/algod:latest
```

Explanation of parts:

* `-p 4190:8080` maps the internal algod REST API to local port 4190.
* `-p 4191:7833` maps the internal kmd REST API to local port 4191.
* `-e NETWORK=mainnet` can be set to any of the supported public networks.
* `-e TELEMETRY_NAME=name` enables telemetry reporting to Algorand for network health analysis. The value of this variable takes precedence over the `name` attribute set in `/etc/algorand/logging.config`.
* `-e FAST_CATCHUP=1` causes fast catchup to start shortly after launching the network.
* `-e START_KMD=1` signals to entrypoint to start the kmd REST API (THIS SHOULD NOT BE USED IN PRODUCTION).
* `-e TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` sets the REST API token to use.
* `-v ${PWD}/data:/algod/data/` mounts a local volume to the data directory, which can be used to restart and upgrade the deployment.

## Mounting the Data Directory

The data directory located at `/algod/data`. Mounting a volume at that location will allow you to shutdown and resume the node.

### Volume Permissions

The container executes in the context of the `algorand` user with UID=999 and GID=999 which is handled differently depending on your operating system or deployment platform. During startup the container temporarily runs as `root` in order to modify the permissions of `/algod/data`. It then changes to the `algorand` user. This can sometimes cause problems, for example if your deployment platform doesn't allow containers to run as the root user.

#### Named Volume

Using a named volume will work without any specific configuration in most cases:

```bash
docker volume create algod-data
docker run -it --rm -d -v algod-data:/algod/data algorand/algod
```

#### Use specific UID and GID

On the host system, ensure the directory being mounted uses UID=999 and GID=999. If the directory already has these permissions you may override the default user with `-u 999:999`.

### Private Network

Private networks work a little bit differently. They are configured with, potentially, several data directories. The default topology supplied with this container is installed to `/algod/`, and has a single node named `data`. This means the private network has a data directory at `/algod/data`, matching the production configuration.

Because the root directory contains some metadata, if persistence of the private network is required, you should mount the volume `/algod/` instead of `/algod/data`. This will ensure the extra metadata is included when changing images.

## Faster Private Network Startup

Generating participation keys may take several minutes. By creating them ahead of time a new private network can be started more quickly. These keys can be reused for multiple networks.

Note that you must provide a template.json file for this operation. [You can find a template here](https://github.com/algorand/go-algorand/blob/master/docker/files/run/devmode_template.json), be sure to replace `NUM_ROUNDS` with your desired number of rounds, such as 3000000.

Use the `goal network pregen` command to generate the files in a mounted directory:
```bash
docker run --rm -it \
    --name pregen \
    -v /path/to/your/template.json:/etc/algorand/template.json \
    -v $(pwd)/pregen:/algod/pregen \
    --entrypoint "/node/bin/goal" \
    algorand/algod:stable network pregen -t /etc/algorand/template.json -p /algod/pregen
```

You will now have a local directory named `pregen` which can be mounted the next time you want to start a network with this template:
```bash
docker run --rm -it --name algod-pregen-run \
    -p 4190:8080 \
    -v /tmp/big_keys.json:/etc/algorand/template.json \
    -v $(pwd)/pregen:/etc/algorand/keys \
    algorand/algod:stable
```
