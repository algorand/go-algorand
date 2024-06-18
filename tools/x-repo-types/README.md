# Cross Repo Type Comparisons

Given two types **X** and **Y** from separate repositories, compare the types and generate a report of any differences to the serialized shape of the types. In particular it ignores different embedding of structs, different field names if `codec` tags are used, and different types if they map to the same primitives.
This tool is designed to be used in CI systems to alert us if a change is made to one repo without a corresponding change to another. For example the `Genesis` type in `go-algorand` and `go-algorand-sdk`. See the [Makefile](./Makefile) for additional examples.

## Example run

```sh
goal-v-sdk-state-delta-xrt:
    x-repo-types --x-package "github.com/algorand/go-algorand/ledger/ledgercore" \
    --x-type "StateDelta" \
    --y-branch "develop" \
    --y-package "github.com/algorand/go-algorand-sdk/v2/types" \
    --y-type "LedgerStateDelta"
```

## Pseudocode

### Cross Type Comparison Process

1. Inside of `tools/x-repo-types` run the command `x-repo-types --x-package X_PACKAGE_NAME ...`
2. `x-repo-types` then does the following:
   1. `go get`'s the package
   2. Populates the template `typeAnalyzer/main.tmpl` with comparison types
   3. Saves it in `typeAnalyzer/main.go`
   4. Executes it
3. `typeAnalyzer/main.go` runs the logic defined in `typeAnalyzer/typeAnalyzer.go`:
   1. using reflection, build up each type's "Type Tree"
   2. compare the trees using the rules outlined below
4. If the template reports back a non-empty diff, exit with an error

### Type Tree Comparison

`func StructDiff(x, y interface{}, exclusions map[string]bool) (TypeNode, TypeNode, *Diff, error)` in `typeAnalyzer/typeAnalyzer.go` implements the following recursive notion of _identical_ types:

* if **X** and **Y** are native simple types (`int`, `uint64`, `string`, ...), they are _identical_ IFF they are the same type
* if both **X** and **Y** are compound types (`struct`, slice, `map`, ...) with each of their child types being _identical_ and with _equivalent serialization metadata_, then they are _identical_
  * _equivalent serialization metadata_ definition:
    * for non-structs: there is no metadata so the metadata are _trivially_ identical
    * for structs:
      * the keys will encode to the same name
      * omission of values based on zeroness, etc. will happen in the same way for both structs
      * embedded structs will be flattened

* ELSE: they are **not** _identical_

### Exceptional cases

There are some cases that break the definition above. For example, `basics.MicroAlgos` is a struct in
`go-algorand` but is an alias for `uint64` in `go-algorand-sdk`. Our serializers know to produce the same
output, but this violates the previous notion of _identical_. Such exceptions are handled by providing the string produced by the type's `TypeNode.String()` method
as an element in the set `diffExclusions` of `typeAnalyzer/typeAnalyzer.go`.
