# Cross Repo Type Comparisons


## Build the `xrt` binary

```sh
make build-xrt
```

## Example run

```sh
./xrt --x-repo "github.com/algorand/go-algorand" \
    --x-package "github.com/algorand/go-algorand/ledger/ledgercore" \
    --x-type "StateDelta" \
    --y-repo "github.com/algorand/go-algorand-sdk/v2@develop" \
    --y-package "github.com/algorand/go-algorand-sdk/v2/types" \
    --y-type "LedgerStateDelta"
```
