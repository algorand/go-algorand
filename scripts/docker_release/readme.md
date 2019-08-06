# Algorand Docker Image 


## Import Docker contatiner  

```cmd
docker import docker import algorand_docker_release_<version>.tar.gz 
```


## Start the docker container for the specified network (devnet, testnet, mainnet)

```cmd
./start_algod_docker.sh <network> 
```

## You can attach to the runing container with the following command:

```cmd
docker exec -it algod-<network> /bin/bash
```