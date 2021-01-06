// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package main

// This tool converts between msgpack and JSON encoding.
//
// For binary data in msgpack, if that binary data appears in a map
// with a string key, this tool base64-encodes that data in JSON and
// appends ":b64" to the key.  The reverse happens for JSON-to-msgpack.
//
// Binary data in msgpack that is not in a map with a string key gets
// base64-encoded into a string (as is the default in go-codec), but
// this tool cannot unambiguously reverse this when converting JSON
// back to msgpack.
//
// Two notable cases that don't fall in the above category are:
//
// (1.) A bare binary data blob at the top level (not in a map)
// (2.) An array/slice of binary data blobs
//
// Be sure that binary data is encoded using msgpack binary types.
// This requires setting WriteExt=true in go-codec at encode time.
//
// As long as base64-encoded data appears in string-keyed maps, as
// mentioned above, this tool should preserve canonicality of msgpack
// encodings across decode/encode.  The one exception is that this tool
// does not omit zero values (as we typically do due to the "omitempty"
// annotation).  So, zero values must be manually removed from JSON data.

import (
	"flag"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/protocol/transcode"
)

var mpToJSON = flag.Bool("d", false, "Decode msgpack to JSON")
var jsonToMp = flag.Bool("e", false, "Encode msgpack from JSON")
var base32Encoding = flag.Bool("b32", false, "Encode binary blobs using base32 instead of base64")
var strictJSON = flag.Bool("strict", false, "Strict JSON decode: turn all keys into strings")

func main() {
	flag.Parse()
	if *mpToJSON && *jsonToMp {
		fmt.Fprintf(os.Stderr, "Cannot specify both -d and -e\n")
		os.Exit(1)
	}

	if !*mpToJSON && !*jsonToMp {
		fmt.Fprintf(os.Stderr, "Must specify one of -d or -e\n")
		os.Exit(1)
	}

	err := transcode.Transcode(*mpToJSON, *base32Encoding, *strictJSON, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
