# Algorand Docker Image 


## Import Docker container  

```cmd
docker import algod_docker_export_${CHANNEL}_${FULLVERSION}.tar.gz 
```


## Start the docker container for the specified network (betanet, devnet, testnet, mainnet)

```cmd
./start_algod_docker.sh ${NETWORK} 
```

## You can attach to the running container with the following command:

```cmd
docker exec -it  algod_${CHANNEL}_${FULLVERSION}_${NETWORK} /bin/bash
```