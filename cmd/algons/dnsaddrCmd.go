// Copyright (C) 2019-2024 Algorand, Inc.
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

	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/network/p2p/dnsaddr"
	"github.com/algorand/go-algorand/tools/network/cloudflare"
)

var (
	dnsaddrDomain string
	secure        bool
	cmdMultiaddrs []string
	nodeSize      int
)

func init() {
	dnsaddrCmd.AddCommand(dnsaddrTreeCmd)

	dnsaddrTreeCmd.Flags().StringVarP(&dnsaddrDomain, "domain", "d", "", "Top level domain")
	dnsaddrTreeCmd.MarkFlagRequired("domain")
	dnsaddrTreeCmd.Flags().BoolVarP(&secure, "secure", "s", true, "Enable dnssec")

	dnsaddrTreeCmd.AddCommand(dnsaddrTreeCreateCmd)
	dnsaddrTreeCreateCmd.Flags().StringArrayVarP(&cmdMultiaddrs, "multiaddrs", "m", []string{}, "multiaddrs to add")
	dnsaddrTreeCreateCmd.Flags().StringVarP(&dnsaddrDomain, "domain", "d", "", "Top level domain")
	dnsaddrTreeCreateCmd.Flags().IntVarP(&nodeSize, "node-size", "n", 50, "Number of multiaddrs entries per TXT record")
	dnsaddrTreeCreateCmd.MarkFlagRequired("domain")
	dnsaddrTreeCreateCmd.MarkFlagRequired("multiaddrs")

	dnsaddrTreeCmd.AddCommand(dnsaddrTreeDeleteCmd)
	dnsaddrTreeDeleteCmd.Flags().StringVarP(&dnsaddrDomain, "domain", "d", "", "Top level domain")
	dnsaddrTreeDeleteCmd.MarkFlagRequired("domain")
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
var dnsaddrTreeDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Recursively resolves and deletes the dnsaddr entries of the given domain",
	Long:  "Recursively resolves and deletes the dnsaddr entries of the given domain",
	Run: func(cmd *cobra.Command, args []string) {
		addr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/dnsaddr/%s", dnsaddrDomain))
		if err != nil {
			fmt.Printf("unable to construct multiaddr for %s : %v\n", dnsaddrDomain, err)
			return
		}
		controller := dnsaddr.NewMultiaddrDNSResolveController(secure, "")
		cfZoneID, cfToken, err := getClouldflareCredentials()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting DNS credentials: %v", err)
			return
		}
		cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfToken)
		var recordsToDelete []cloudflare.DNSRecordResponseEntry
		err = dnsaddr.Iterate(addr, controller, func(entryFrom multiaddr.Multiaddr, entries []multiaddr.Multiaddr) error {
			domain, _ := entryFrom.ValueForProtocol(multiaddr.P_DNSADDR)
			name := fmt.Sprintf("_dnsaddr.%s", domain)
			fmt.Printf("listing records for %s\n", name)
			records, err0 := cloudflareDNS.ListDNSRecord(context.Background(), "TXT", name, "", "", "", "")
			if err0 != nil {
				fmt.Printf("erroring listing dns records for %s %s\n", domain, err)
				return err
			}
			for _, record := range records {
				fmt.Printf("found record to delete %s:%s\n", record.Name, record.Content)
				recordsToDelete = append(recordsToDelete, record)
			}
			return nil
		})
		if err != nil {
			fmt.Printf("%s\n", err.Error())
			return
		}
		err = checkedDelete(recordsToDelete, cloudflareDNS)
		if err != nil {
			fmt.Printf("error deleting records: %s\n", err)
		}
	},
}

var dnsaddrTreeCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates a tree of entries containing the multiaddrs at the provided root domain",
	Long:  "Creates a tree of entries containing the multiaddrs at the provided root domain",
	Run: func(cmd *cobra.Command, args []string) {
		if len(cmdMultiaddrs) == 0 {
			fmt.Printf("must provide multiaddrs to put in the DNS records")
			return
		}
		// Generate the dnsaddr entries required for the full tree
		var dnsaddrsTo []string
		for i := 0; i < len(cmdMultiaddrs)/nodeSize; i++ {
			dnsaddrsTo = append(dnsaddrsTo, fmt.Sprintf("%d%s", i, dnsaddrDomain))
		}
		dnsaddrsFrom := []string{fmt.Sprintf("_dnsaddr.%s", dnsaddrDomain)}
		entries, err := getEntries(dnsaddrsFrom[0], "TXT")
		if err != nil {
			fmt.Printf("failed fetching entries for %s\n", dnsaddrsFrom[0])
			os.Exit(1)
		}
		if len(entries) > 0 {
			for _, entry := range entries {
				fmt.Printf("found entry %s => %s\n", entry.Name, entry.Content)
			}
			fmt.Printf("found entries already existing at %s, bailing out\n", dnsaddrsFrom[0])
			os.Exit(1)
		}
		for _, addrTo := range dnsaddrsTo {
			dnsaddrsFrom = append(dnsaddrsFrom, fmt.Sprintf("_dnsaddr.%s", addrTo))
		}
		for _, from := range dnsaddrsFrom {
			for i := 0; i < nodeSize; i++ {
				if len(dnsaddrsTo) > 0 {
					newDnsaddr := fmt.Sprintf("dnsaddr=/dnsaddr/%s", dnsaddrsTo[len(dnsaddrsTo)-1])
					fmt.Printf("writing %s => %s\n", from, newDnsaddr)
					err := doAddTXT(from, newDnsaddr)
					if err != nil {
						fmt.Printf("failed writing dnsaddr entry %s: %s\n", newDnsaddr, err)
						os.Exit(1)
					}
					dnsaddrsTo = dnsaddrsTo[:len(dnsaddrsTo)-1]
					continue
				}
				newDnsaddr := fmt.Sprintf("dnsaddr=%s", cmdMultiaddrs[len(cmdMultiaddrs)-1])
				fmt.Printf("writing %s => %s\n", from, newDnsaddr)
				err := doAddTXT(from, newDnsaddr)
				if err != nil {
					fmt.Printf("failed writing dns entry %s\n", err)
					os.Exit(1)
				}
				cmdMultiaddrs = cmdMultiaddrs[:len(cmdMultiaddrs)-1]
				if len(cmdMultiaddrs) == 0 {
					return
				}
			}
		}
	},
}
