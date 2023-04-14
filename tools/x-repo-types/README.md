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

## Pseudocode

### Cross Type Comparison Process

1. Inside of `tools/x-repo-types` run the command `./xrt --x-package X_PACKAGE_NAME ...`
2. `xrt` then does the following:
   1. `go get`'s the package
   2. `go build`'s it
   3. executes a the template `xrt_tmpl.go.tmpl` in a temp folder, providing it the type information for the types to be compared
3. `xrt_tmpl.go.tmpl` runs the following logic:
   1. using reflection, build up each type's "Type Tree"
   2. compare the trees using the rules outlined below
4. If the template reports back a non-empty diff, exit with an error.

### Type Tree Comparison

`func SerializationDiff(x, y Target, exclusions map[string]bool) (*Diff, error)` in `xrt_tmpl.go` implements the following recursive notion of _identical_ types:

* if **X** and **Y** are native types (`int`, `uint64`, `string`, ...), they are _identical_ IFF they are the same type
* if both **X** and **Y** are compound types (`struct`, slice, `map`, ...) with each of their child types being _identical_, then they are _identical_
* else: they are **not** _identical_

### Exceptional cases

There are some cases that break the definition above. For example, `basics.MicroAlgos` is a struct in
`go-algorand` but is an alias for `uint64` in `go-algorand-sdk`. Our serializers know to produce the same
output, but this violates the previous notion of _identical_. Such exceptions are handled by providing
