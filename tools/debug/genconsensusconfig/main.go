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

// doberman will tell you when there's something wrong with the system
package main

import (
	"fmt"
	"os"

	"github.com/algorand/go-algorand/config"
)

func main() {
	path, err := os.Getwd()
	if err != nil {
		fmt.Printf("Unable to retieve current working directory : %v", err)
		os.Exit(1)
	}
	err = config.SaveConfigurableConsensus(path, config.Consensus)
	if err != nil {
		fmt.Printf("Unable to save file : %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}
