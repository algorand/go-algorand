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

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/network/p2p/dnsaddr"
)

var (
	dnsaddrDomain string
	secure        bool
)

func init() {
	dnsaddrCmd.AddCommand(dnsaddrTreeCmd)

	dnsaddrTreeCmd.Flags().StringVarP(&dnsaddrDomain, "domain", "d", "", "Top level domain")
	dnsaddrTreeCmd.MarkFlagRequired("domain")
	dnsaddrTreeCmd.Flags().BoolVarP(&secure, "secure", "s", true, "Enable dnssec")
}

var dnsaddrCmd = &cobra.Command{
	Use:   "dnsaddr",
	Short: "Get, Set, and List Dnsaddr entries",
	Long:  "Get, Set, and List Dnsaddr entries",
	Run: func(cmd *cobra.Command, args []string) {
		// Fall back
		cmd.HelpFunc()(cmd, args)
	},
}

var dnsaddrTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Recursively resolves and lists the dnsaddr entries of the given domain",
	Long:  "Recursively resolves and lists the dnsaddr entries of the given domain",
	Run: func(cmd *cobra.Command, args []string) {
		controller := dnsaddr.NewMultiaddrDNSResolveController(secure, "")
		addrs, err := dnsaddr.MultiaddrsFromResolver(dnsaddrDomain, controller)
		if err != nil {
			fmt.Printf("%s\n", err.Error())
			return
		}
		for _, addr := range addrs {
			fmt.Printf("%s\n", addr.String())
		}
	},
}
