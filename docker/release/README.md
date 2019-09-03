# Running the Algorand Docker Image 

### Download the Algorand Docker Image Export from the Releases area  

```cmd
https://releases.algorand.com/
```

The Docker Image export file name will be according to this format:

```cmd
algod_docker_export_${CHANNEL}_${FULLVERSION}.tar.gz
```

The CHANNEL specifies the release channel (e.g., 'stable', or 'nightly').
The FULLVERSION specifies the version of the release (e.g., 1.0.29). 

### Import the Docker container  

```cmd
docker import algod_docker_export_${CHANNEL}_${FULLVERSION}.tar.gz 
```

### Start the docker container for the specified network (betanet, devnet, testnet, mainnet)

```cmd
./start_algod_docker.sh ${NETWORK} 
```

The NETWORK specifies what network to connect to (e.g., 'devnet', 'testnet', 'betanet', 'mainnet')

### You can attach to the running container with the following command:

```cmd
docker exec -it  algod_${CHANNEL}_${FULLVERSION}_${NETWORK} /bin/bash
```