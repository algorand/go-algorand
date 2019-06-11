# How to use the catch up server 

 ## Online machine 

 1. Create a new folder `mkdir data`.
2. Download all blocks from the relevant network. For example, to download from `testNet` with genesis `testnet-v31.0` run the following command 
    ```bash
    ./catchupsrv -dir data -download -network testnet -genesis testnet-v31.0
    ```
2. Copy the `data` dir to an airgapped machine using you favorite method


 ## Offline (airgapped) machine 
1. Run the catch server on some free port (e.g. 50000) and point it to your data dir
    ```bash
    ./catchupsrv -dir data -addr localhost:50000
    ```
2. Run algod with following command. (where xx is your algorand data directory)
    ```bash
    ./goal node start -d xx -p localhost:50000
    ```

 now `algod` will catch up from the catch up server