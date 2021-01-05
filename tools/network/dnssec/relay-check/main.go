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

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/tools/network/dnssec"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Printf(`Usage: %s <service> <proto> <name>
Where\n
<service> is a SRV service, for example 'algobootstrap',
<proto> is SRV protocol ('tcp', 'udp'),
<name> is SRV name like 'mainnet.algorand.network
`, os.Args[0])
		os.Exit(1)
	}

	srvService := os.Args[1]
	srvProto := os.Args[2]
	srvName := os.Args[3]

	success := make(map[string]bool)
	errors := make(map[string]string)
	nonSigned := make(map[string]string)
	r := dnssec.MakeDefaultDnssecResolver("", logging.Base())
	_, entries, err := r.LookupSRV(context.Background(), srvService, srvProto, srvName)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	for _, entry := range entries {
		_, err := r.LookupIPAddr(context.Background(), entry.Target)
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
