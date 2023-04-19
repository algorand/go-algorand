// Copyright (C) 2019-2023 Algorand, Inc.
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

/* THIS FILE ONLY EXISTS FOR DEBUGGING AND TO MAKE THE BUILD HAPPY */

package main

import (
	"fmt"
	"os"
	"reflect"

	ypkg "github.com/algorand/go-algorand/data/bookkeeping"
	xpkg "github.com/algorand/go-algorand/ledger/ledgercore"
)

func main() {
	x := reflect.TypeOf(xpkg.StateDelta{})
	y := reflect.TypeOf(ypkg.Genesis{})

	// ---- BUILD ---- //

	xRoot := Type{Type: x, Kind: x.Kind()}
	fmt.Printf("Build the Type Tree for %s\n\n", &xRoot)
	xRoot.Build()
	xTgt := Target{Edge{Name: fmt.Sprintf("%q", x)}, xRoot}

	yRoot := Type{Type: y, Kind: y.Kind()}
	fmt.Printf("Build the Type Tree for %s\n\n", &yRoot)
	yRoot.Build()
	yTgt := Target{Edge{Name: fmt.Sprintf("%q", y)}, yRoot}

	// ---- DEBUG ---- //

	/*
		xRoot.Print()
		fmt.Printf("\n\nSerialization Tree of %q\n\n", x)
		xTgt.PrintSerializable()

		yRoot.Print()
		fmt.Printf("\n\nSerialization Tree of %q\n\n", x)
		yTgt.PrintSerializable()
	*/

	// ---- STATS ---- //

	LeafStatsReport(xTgt)
	LeafStatsReport(yTgt)

	// ---- DIFF ---- //

	fmt.Printf("\n\nCompare the Type Trees %q v %q\n", x, y)
	diff, err := SerializationDiff(xTgt, yTgt, diffExclusions)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	Report(xTgt, yTgt, diff)

	if !diff.Empty() {
		// signal the this "test" has failed
		os.Exit(1)
	}
}
