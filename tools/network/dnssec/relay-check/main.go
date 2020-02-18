// Copyright (C) 2019-2020 Algorand, Inc.
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

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/algorand/go-algorand/tools/network/dnssec"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <DOMAIN-NAME>\n\tWhere <DOMAIN-NAME> is a name containing SRV record, like '_algobootstrap._tcp.mainnet.algorand.network'\n", os.Args[0])
		os.Exit(1)
	}

	srvName := os.Args[1]

	success := make(map[string]bool)
	errors := make(map[string]string)
	nonSigned := make(map[string]string)
	r := dnssec.MakeDnssecResolver(nil, time.Second)
	entries, err := r.LookupSRV(srvName)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	for _, entry := range entries {
		_, err := r.LookupIPRecursive(entry.Target, 4)
		if err == nil {
			success[entry.Target] = true
		} else {
			if strings.HasPrefix(err.Error(), "no signature in DNS response for") {
				nonSigned[entry.Target] = err.Error()[len("no signature in DNS response for"):]
			} else {
				errors[entry.Target] = err.Error()
			}
		}
	}
	fmt.Printf("Signed responses:\n")
	for k := range success {
		fmt.Printf("%s\n", k)
	}
	fmt.Printf("\nNon signed entires\n")
	for k, v := range nonSigned {
		fmt.Printf("%s -> %s\n", k, v)
	}
	fmt.Printf("\nErrors\n")
	for k, v := range errors {
		fmt.Printf("%s: %s\n", k, v)
	}
}
