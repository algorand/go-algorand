# Message Pack

The Algorand protocol uses a modified message pack encoding for canonical
messages used throughout the system. Details about [Canonical Messagepack](https://github.com/algorandfoundation/specs/blob/6996ac344158ca90a430bc8601fc29b150b0aa3f/dev/crypto.md#canonical-msgpack)
can be found in the formal specification. What follows here are some of the
implementation details that are useful to know.

## Why Message Pack

Generally speaking, message pack is small and fast compared to many alternative
encodings. There are other encodings which would have also been suitable, but a
choice needed to be made.

## Libraries

### [algorand/go-codec](https://github.com/algorand/go-codec)
Forked from [ugorji/go](https://github.com/ugorji/go)

This library uses `codec:` annotations in the go structs to define encodings.
It is used widely throughout the code for message pack and JSON encoding when
needed. It provides features that the builtin `encoding/json` including things
like allowing integer map keys.

### [algorand/msgp](https://github.com/algorand/msgp)
Forked from [tinylib/msgp](https://github.com/tinylib/msgp)

This library is used to generate code to serialize and deserialize message pack
messages without using reflection. It has been modified to be compatible with
the `codec:` annotations used by go-codec. The generated methods are
significantly faster than the reflection based go-codec versions. For a rough
idea of the performance difference, [here are some benchmarks for Transactions](https://github.com/algorand/go-algorand/pull/4266).

## Code generation

Install `msgp` with [install_buildtools.sh](scripts/buildtools/install_buildtools.sh) and use it with `make msgp`.

The generated Marshal and Unmarshal utilities are located in `msgp_gen.go`
files. Update `MSGP_GENERATE` in the Makefile to add another package.
