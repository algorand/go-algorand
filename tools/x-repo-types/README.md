# Cross Repo Type Comparisons

Given two types **X** and **Y** from separate repositories, compare the types and generate a report of any differences to the serialized shape of the types. In particular it ignores different embedding of structs, different field names if `codec` tags are used, and different types if they map to the same primitives.
This tool is designed to be used in CI systems to alert us if a change is made to one repo without a corresponding change to another. For example the `Genesis` type in `go-algorand` and `go-algorand-sdk`. See the [Makefile](./Makefile) for additional examples.

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
   3. executes the template `xrt_tmpl.go.tmpl` in a temp folder, providing it the type information for the types to be compared
3. `xrt_tmpl.go.tmpl` runs the following logic:
   1. using reflection, build up each type's "Type Tree"
   2. compare the trees using the rules outlined below
4. If the template reports back a non-empty diff, exit with an error

### Type Tree Comparison

`func SerializationDiff(x, y Target, exclusions map[string]bool) (*Diff, error)` in `xrt_tmpl.go` implements the following recursive notion of _identical_ types:

* if **X** and **Y** are native types (`int`, `uint64`, `string`, ...), they are _identical_ IFF they are the same type
* if both **X** and **Y** are compound types (`struct`, slice, `map`, ...) with each of their child types being _identical_ and with _equivalent serialization metadata_, then they are _identical_
  * _equivalent serialization metadata_ definition:
    * for non-structs: there is no metadata so the metadata are _trivially_ identical
    * for structs:
      * the keys will encode to the same name
      * omission of values based on zeroness, etc. will happen in the same way for both structs
* ELSE: they are **not** _identical_

### Exceptional cases

There are some cases that break the definition above. For example, `basics.MicroAlgos` is a struct in
`go-algorand` but is an alias for `uint64` in `go-algorand-sdk`. Our serializers know to produce the same
output, but this violates the previous notion of _identical_. Such exceptions are handled by providing the string produced by the type's `Type.String()` method
as en element in the set `diffExclusions` of `xrt_tmpl.go`.

## For developing this tool

`xrt_tmpl.go` is provided for ease of development, but is not strictly required for running the tool. You can
run it as a standalone app and debug the algorithms with it. To run `xrt_tmpl.go`:

1. Rename its `Main()` function to `main()` (and to pass compilation, rename `xrt.go`'s `main()`)
2. Replace the `xpkg, ypkg` imports with the packages you want to test
3. Replace `x, y` by the types you'd like to take the diff

NOTE: `make build-xrt` generates `xrt_tmpl.go.tmpl` from `xrt_tmpl.go` using specially crafted comments to
signal how to modify the code.
