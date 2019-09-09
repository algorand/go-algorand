# Running the Algorand Docker Image 

###Prerequisites
Verify that you have a running Docker Engine on your local system.  Instructions for installing Docker are available on the Docker web site:
```cmd
https://docs.docker.com/
```

### Import the Algorand Docker container  

```cmd
docker import algod_docker_export_${CHANNEL}_${FULLVERSION}.tar.gz 
```
The CHANNEL specifies the release channel (e.g., 'stable', or 'nightly').
The FULLVERSION specifies the version of the release (e.g., 1.0.29). 

### Start the docker container for the specified network (betanet, devnet, testnet, mainnet)

```cmd
./start_algod_docker.sh ${NETWORK} 
```

The NETWORK specifies what network to connect to (e.g., 'devnet', 'testnet', 'betanet', 'mainnet')

### You can attach to the running container with the following command:

```cmd
docker exec -it  algod_${CHANNEL}_${FULLVERSION}_${NETWORK} /bin/bash
```

###Stopping the Docker Container:
Run the following command to stop the docker container:
```cmd
docker stop algod_${CHANNEL}_${FULLVERSION}_${NETWORK}
```

To remove the container from the Docker environment:

```cmd
docker container rm algod_${CHANNEL}_${FULLVERSION}_${NETWORK}
```
###Container Persistence 
When starting the Algod Docker instance, a Docker volume is created to persist the node data directory external from the container.  This allows updating the docker container and reusing an existing data directory with the new version.  A volume is created for each instantiated network (i.e. betanet, devnet, testnet, or mainnet). 

The existing volumes can be determined using the docker volume command.
```cmd
docker volume ls
```
To remove a volume:
```cmd
docker volume rm alogd-${NETWORK}
```

