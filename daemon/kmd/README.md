# kmd - Key Management Daemon

## Overview
kmd is the Key Management Daemon, the process responsible for securely managing spending keys. It is the implementation of the design [specified here.](https://docs.google.com/document/d/1j7sLC2BphSFqd76GEIJvw4GpY2tNW7nmk_Ea7UfBEWc/edit?usp=sharing)

## Useful facts
- kmd has a data directory separate from algod's data directory. By default, however, the kmd data directory is in the `kmd` subdirectory of algod's data directory.
- kmd starts an HTTP API server on `localhost:7833` by default.
- You talk to the HTTP API by sending json-serialized request structs from the `kmdapi` package.

## Preventing memory from swapping to disk
kmd tries to ensure that secret keys never touch the disk unencrypted. At startup, kmd tries to call [`mlockall`](https://linux.die.net/man/2/mlockall) in order to prevent the kernel from swapping memory to disk. You can check `kmd.log` after starting kmd to see if the call succeeded.

In order for the `mlockall` call to succeed, your kernel must support `mlockall`, and the user running kmd must be able to lock the necessary amount of memory. On many linux distributions, you can achieve this by calling `sudo setcap cap_ipc_lock+ep /path/to/kmd`. We also provide a make target for this: run `make capabilities` from the `go-algorand` project root.

## Project structure
- `./`
	- `api/v1/`
		- This folder contains all of the HTTP handlers for the kmd API V1. In general, these handlers each parse a `kmdapi.APIV1Request`, and use it to run commands against a wallet.
		- Initializing these handlers requires passing a `session.Manager` to handle wallet auth and persistent state between requests.
	- `client/`
		- The `client` package provides `client.KMDClient`. `client.KMDClient.DoV1Request` infers the HTTP endpoint and method from the request type, serializes the request with msgpack, makes the request over the unix socket, and deserializes a `kmdapi.APIV1Response`.
		- The `client` package also provides wrappers for these API calls in `wrappers.go`
	- `config/`
		- This folder contains code that parses `kmd_config.json` and merges values from that file with any default values.
	- `lib/`
		- This folder contains the `kmdapi` package, which provides the canonical structs used for requests and responses.
	- `server/`
		- The `server` package is in charge of starting and stopping the kmd API server.
	- `session/`
		- The `session` package provides `session.Manager`, which allows users to interact with wallets without having to enter a password repeatedly. It achieves this by temporarily storing wallet keys in memory once they have been decrypted.
	- `wallet/`
		- `driver`
			- This folder contains the definitions of a "Wallet Driver", as well as the "SQLite Wallet Driver", kmd's default wallet backend.
			- Wallet Drivers are responsible for creating and retrieving Wallets, which store, retrieve, generate, and perform cryptographic operations on spending keys.
