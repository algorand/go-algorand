
To install the service and it's associated keys:

```
# Sample arguments. Use your own.
make install SVCEXE="C:\src\go-algorand-rl\windows\algodsvc\algodsvc.exe" NETWORK=testnet ALGODEXE="E:\algod\algod.exe" NODEDATADIR="E:\algod\data"
```

Replace SVCEXE, ALGODEXE, NODEDATADIR with your desired locations for service executable, algod daemon executable and data directory. 
Use NETWORK to specify testnet,mainnet or betanet.

This way algodsvc can serve multiple algod daemons for different networks in Windows systems.

Use the following target to remove service entry from Windows registry:

```
make uninstall NETWORK=<betanet|mainnet|testnet> 
```


