# How to use the catchup server 

The catchup server allow to download the blockchain into an airgapped machine, so that it is possible to run `algod` on the airgapped machine without access to the Internet.

## Online machine: download the blockchain

1. Create a new folder `mkdir data`.
2. Download all blocks from the relevant network. For example, to download from `mainnet` with genesis `mainnet-v1.0` run the following command: 
    ```bash
    catchupsrv -dir data -download -network mainnet -genesis mainnet-v1.0
    ```
2. Copy the `data` dir to an airgapped machine using you favorite method.

## Offline (airgapped) machine 

1. Run the catchup server on some free port (e.g., 50000) and point it to your data dir:
    ```bash
    catchupsrv -dir data -addr localhost:50000
    ```
2. Run `algod` with following command (where `xx` is your algorand data directory):
    ```bash
    goal node start -d xx -p localhost:50000
    ```

Now `algod` will catch up from the catchup server.