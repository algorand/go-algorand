# Algod Container

General purpose algod container image.

## Image Configuration

There are a number of special files and environment variables used to control how a container is started.

### Default Configuration

By default the following config.json overrides are applied:

| Setting | Value |
| ------- | ----- |
| GossipFanout | 1 |
| EndpointAddress | 0.0.0.0:8080 |
| IncomingConnectionsLimit | 0 |
| Archival | false |
| IsIndexerActive | false |
| EnableDeveloperAPI | true |

### Environment Variables

The following environment variables can be supplied. Except when noted, it is possible to reconfigure deployments even after the data directory has been initialized.

| Variable | Description |
| -------- | ----------- |
| NETWORK       | Leave blank for a private network, otherwise specify one of mainnet, betanet, testnet, or devnet. Only used during a data directory initialization. |
| FAST_CATCHUP  | If set on a public network, attempt to start fast-catchup during initial config. |
| TELEMETRY_NAME| If set on a public network, telemetry is reported with this name. |
| DEV_MODE      | If set on a private network, enable dev mode. Only used during data directory initialization. |
| NUM_ROUNDS    | If set on a private network, override default of 30000 participation keys. |
| TOKEN         | If set, overrides the REST API token. |
| ADMIN_TOKEN   | If set, overrides the REST API admin token. |

### Special Files

Configuration can be modified by specifying certain files. These can be changed each time you start the container if the data directory is a mounted volume.

| File | Description |
| ---- | ----------- |
| /etc/config.json | Override default configurations by providing your own file. |
| /etc/algod.token | Override default randomized REST API token. |
| /etc/algod.admin.token | Override default randomized REST API admin token. |

TODO: `/etc/template.json` for overriding the private network topology.

## Example Configuration

The following command launches a container configured with one of the public networks:

```bash
docker run --rm -it \
    -p 4190:8080 \
    -e NETWORK=mainnet \
    -e FAST_CATCHUP=1 \
    -e TELEMETRY_NAME=name \
    -e TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    -v ${PWD}/data:/algod/data/ \
    --name mainnet-container \
    algorand/algod:latest
```

Explanation of parts:

* `-p 4190:8080` maps the internal algod REST API to local port 4190
* `-e NETWORK=` can be set to any of the supported public networks.
* `-e FAST_CATCHUP=` causes fast catchup to start shortly after launching the network.
* `-e TELEMETRY_NAME=` enables telemetry reporting to Algorand for network health analysis.
* `-e TOKEN=` sets the REST API token to use.
* `-v ${PWD}/data:/algod/data/` mounts a local volume to the data directory, which can be used to restart and upgrade the deployment.

## Mounting the Data Directory

The data directory located at `/algod/data`. Mounting a volume at that location will allow you to shutdown and resume the node.

### Private Network

Private networks work a little bit differently. They are configured with, potentially, several data directories. The default topology supplied with this container is installed to `/algod/`, and has a single node named `data`. This means the private network has a data directory at `/algod/data`, matching the production configuration.

Because the root directory contains some metadata, if persistence of the private network is required, you should mount the volume `/algod/` instead of `/algod/data`. This will ensure the extra metadata is included when changing images.
