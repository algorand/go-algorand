// Copyright (C) 2019-2025 Algorand, Inc.
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
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/cmd/algorelay/eb"
	"github.com/algorand/go-algorand/tools/network/cloudflare"
	"github.com/algorand/go-algorand/util/codecs"
)

var (
	inputFileArg    string
	outputFileArg   string
	srvDomainArg    string // e.g. algorand.network
	nameDomainArg   string // e.g. algorand-mainnet.network
	defaultPortArg  uint16
	dnsBootstrapArg string // e.g. mainnet or testnet
	recordIDArg     int64

	cfToken string
)

var nameRecordTypes = []string{"A", "CNAME", "SRV"}

const metricsPort = uint16(9100)

func init() {
	cfToken = os.Getenv("CLOUDFLARE_API_TOKEN")
	if cfToken == "" {
		panic(makeExitError(1, "CLOUDFLARE_API_TOKEN credentials missing from ENV"))
	}

	rootCmd.AddCommand(checkCmd)

	checkCmd.Flags().StringVarP(&inputFileArg, "inputfile", "i", "", "File containing Relay data")
	checkCmd.MarkFlagRequired("inputfile")

	checkCmd.Flags().StringVarP(&outputFileArg, "outputfile", "o", "", "File to output results to, as JSON")

	checkCmd.Flags().Int64Var(&recordIDArg, "id", 0, "Specific Datastore record ID to check (all if not specified)")

	checkCmd.Flags().StringVarP(&srvDomainArg, "srvdomain", "s", "", "Domain name for SRV records")
	checkCmd.MarkFlagRequired("srvdomain")
	checkCmd.Flags().StringVarP(&nameDomainArg, "namedomain", "n", "", "Domain name for A/CNAME records")
	checkCmd.MarkFlagRequired("namedomain")
	checkCmd.Flags().Uint16VarP(&defaultPortArg, "defaultport", "p", 4160, "Default listening port (eg 4160)")
	checkCmd.MarkFlagRequired("defaultport")
	checkCmd.Flags().StringVarP(&dnsBootstrapArg, "dnsbootstrap", "b", "", "Bootstrap name for SRV records (eg mainnet)")
	checkCmd.MarkFlagRequired("dnsbootstrap")

	rootCmd.AddCommand(updateCmd)

	updateCmd.Flags().StringVarP(&inputFileArg, "inputfile", "i", "", "File containing Relay data")
	updateCmd.MarkFlagRequired("inputfile")

	updateCmd.Flags().StringVarP(&outputFileArg, "outputfile", "o", "", "File to output results to, as JSON")

	updateCmd.Flags().Int64Var(&recordIDArg, "id", 0, "Specific Datastore record ID to check (all if not specified)")

	updateCmd.Flags().StringVarP(&srvDomainArg, "srvdomain", "s", "", "Domain name for SRV records")
	updateCmd.MarkFlagRequired("srvdomain")
	updateCmd.Flags().StringVarP(&nameDomainArg, "namedomain", "n", "", "Domain name for A/CNAME records")
	updateCmd.MarkFlagRequired("namedomain")
	updateCmd.Flags().Uint16VarP(&defaultPortArg, "defaultport", "p", 4160, "Default listening port (eg 4160)")
	updateCmd.MarkFlagRequired("defaultport")
	updateCmd.Flags().StringVarP(&dnsBootstrapArg, "dnsbootstrap", "b", "", "Bootstrap name for SRV records (eg mainnet)")
	updateCmd.MarkFlagRequired("dnsbootstrap")
}

func loadRelays(file string) []eb.Relay {
	var relays []eb.Relay
	err := codecs.LoadObjectFromFile(file, &relays)
	if err != nil {
		err = fmt.Errorf("Unable to load relays file - %v", err)
		panic(makeExitError(1, err.Error()))
	}
	return relays
}

type checkResult struct {
	ID      int64
	Success bool
	Error   string `json:",omitempty"`
}

type dnsContext struct {
	nameEntries map[string]string
	bootstrap   srvService
	metrics     srvService
	srvZoneID   string
	nameZoneID  string
}

type srvService struct {
	serviceName string
	entries     map[string]uint16
	shortName   string
	networkName string
}

func makeDNSContext() *dnsContext {
	cloudflareCred := cloudflare.NewCred(cfToken)

	nameZoneID, err := cloudflareCred.GetZoneID(context.Background(), nameDomainArg)
	if err != nil {
		panic(makeExitError(1, err.Error()))
	}

	nameEntries, err := getReverseMappedEntries(nameZoneID, nameRecordTypes)
	if err != nil {
		panic(makeExitError(1, err.Error()))
	}

	srvZoneID, err := cloudflareCred.GetZoneID(context.Background(), srvDomainArg)
	if err != nil {
		panic(makeExitError(1, err.Error()))
	}

	bootstrap, err := getSrvRecords("_algobootstrap", dnsBootstrapArg+"."+srvDomainArg, srvZoneID)
	if err != nil {
		panic(makeExitError(1, err.Error()))
	}

	metrics, err := getSrvRecords("_metrics", srvDomainArg, srvZoneID)
	if err != nil {
		panic(makeExitError(1, err.Error()))
	}

	return &dnsContext{
		nameEntries: nameEntries,
		bootstrap:   bootstrap,
		metrics:     metrics,
		srvZoneID:   srvZoneID,
		nameZoneID:  nameZoneID,
	}
}

func makeService(shortName, networkName string) srvService {
	return srvService{
		serviceName: shortName + "._tcp." + networkName,
		entries:     make(map[string]uint16),
		shortName:   shortName,
		networkName: networkName,
	}
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check status of all relays",
	Run: func(cmd *cobra.Command, args []string) {
		relays := loadRelays(inputFileArg)

		context := makeDNSContext()

		checkOne := recordIDArg != 0
		results := make([]checkResult, 0)
		anyCheckError := false

		relaysDNSAlias := make(map[string]bool)
		enabledRelaysDNSAlias := make(map[string]bool)
		relayHostNames := make(map[string]bool)

		for _, relay := range relays {
			relaysDNSAlias[relay.DNSAlias] = true
			if checkOne && relay.ID != recordIDArg {
				continue
			}

			if !relay.CheckSuccess {
				continue
			}
			enabledRelaysDNSAlias[relay.DNSAlias] = true
			relayHostNames[strings.Split(relay.Address, ":")[0]] = true

			const checkOnly = true
			name, port, err := ensureRelayStatus(checkOnly, relay, nameDomainArg, srvDomainArg, defaultPortArg, context)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%d] ERROR: %s: %s\n", relay.ID, relay.Address, err)
				results = append(results, checkResult{
					ID:      relay.ID,
					Success: false,
					Error:   err.Error(),
				})
				anyCheckError = true
			} else {
				fmt.Printf("[%d] OK: %s -> %s:%d\n", relay.ID, relay.Address, name, port)
				results = append(results, checkResult{
					ID:      relay.ID,
					Success: true,
				})
			}

			if checkOne {
				break
			}
		}

		// look for orphan _algobootstrap records that aren't represented by this relay file.
		if context.bootstrap.entries != nil {
			for bootstrap := range context.bootstrap.entries {
				alias := strings.Split(bootstrap, ".")[0]
				if enabledRelaysDNSAlias[alias] {
					continue
				}

				if relaysDNSAlias[alias] {
					fmt.Printf("WARN : disabled relay %s has a _algobootstrap entry\n", bootstrap)
				} else {
					fmt.Printf("INFO : orphan relay %s has a _algobootstrap entry\n", bootstrap)
				}
			}
		}

		// look for orphan _metrics records that aren't represented by this relay file.
		if context.metrics.entries != nil {
			for metrics := range context.metrics.entries {
				alias := strings.Split(metrics, ".")[0]
				if enabledRelaysDNSAlias[alias] {
					continue
				}
				if relaysDNSAlias[alias] {
					fmt.Printf("WARN : disabled relay %s has a _metrics entry\n", metrics)
				} else {
					fmt.Printf("INFO : orphan relay %s has a _metrics entry\n", metrics)
				}
			}
		}
		for name, entry := range context.nameEntries {
			if relayHostNames[name] {
				continue
			}
			alias := strings.Split(entry, ".")[0]
			if enabledRelaysDNSAlias[alias] {
				// if we have an entry for that, than it just mean that it wasn't updated yet.
				continue
			}
			fmt.Printf("INFO : orphan DNS entry %s -> %s\n", entry, name)

		}

		if outputFileArg != "" {
			codecs.SaveObjectToFile(outputFileArg, &results, true)
		}

		// Only return success if all checked out
		if anyCheckError {
			os.Exit(-1)
		}
	},
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Updates configuration for all relays to match the expectations",
	Run: func(cmd *cobra.Command, args []string) {
		relays := loadRelays(inputFileArg)

		context := makeDNSContext()

		updateOne := recordIDArg != 0
		results := make([]checkResult, 0)
		anyUpdateError := false

		for _, relay := range relays {
			if updateOne && relay.ID != recordIDArg {
				continue
			}

			const checkOnly = false
			name, port, err := ensureRelayStatus(checkOnly, relay, nameDomainArg, srvDomainArg, defaultPortArg, context)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%d] ERROR: %s: %s\n", relay.ID, relay.Address, err)
				results = append(results, checkResult{
					ID:      relay.ID,
					Success: false,
					Error:   err.Error(),
				})
				anyUpdateError = true
			} else {
				if relay.CheckSuccess {
					fmt.Printf("[%d] OK: %s -> %s:%d\n", relay.ID, relay.Address, name, port)
				} else {
					fmt.Printf("[%d] OK: %s removed ( if it was there )\n", relay.ID, relay.Address)
				}
				results = append(results, checkResult{
					ID:      relay.ID,
					Success: true,
				})
			}

			if updateOne {
				break
			}
		}

		if outputFileArg != "" {
			codecs.SaveObjectToFile(outputFileArg, &results, true)
		}

		// Only return success if all checked out
		if anyUpdateError {
			os.Exit(-1)
		}
	},
}

func ensureRelayStatus(checkOnly bool, relay eb.Relay, nameDomain string, srvDomain string, defaultPort uint16, ctx *dnsContext) (srvName string, srvPort uint16, err error) {
	var port uint16
	target, portString, err := net.SplitHostPort(relay.Address)
	if err != nil {
		target = relay.Address
		port = defaultPort
	} else {
		var port64 uint64
		port64, err = strconv.ParseUint(portString, 10, 16)
		if err != nil {
			return
		}
		port = uint16(port64)
	}

	if target == "" {
		err = fmt.Errorf("'%s' - target host is empty", relay.Address)
		return
	}

	if port == 0 {
		err = fmt.Errorf("%s - port cannot be zero", relay.Address)
		return
	}

	// Error if target has another name entry - target should be relay provider's domain so shouldn't be possible
	if mapsTo, has := ctx.nameEntries[target]; has {
		err = fmt.Errorf("relay target has a DNS Name entry and should not (%s -> %s)", target, mapsTo)
		return
	}

	names, err := getTargetDNSChain(ctx.nameEntries, target)
	if err != nil {
		return
	}

	// Error if no entries
	if len(names) == 1 {
		if checkOnly {
			err = fmt.Errorf("no DNS entries found mapping to %s in '%s'", target, nameDomain)
			return
		}
	}

	topmost := names[len(names)-1]

	if relay.DNSAlias == "" {
		err = fmt.Errorf("missing DNSAlias name")
		return
	}

	targetDomainAlias := relay.DNSAlias + "." + nameDomain

	if topmost != targetDomainAlias {
		if checkOnly {
			err = fmt.Errorf("topmost DNS name is not the assigned DNS Alias (wanted: %s, found %s)",
				relay.DNSAlias, topmost)
			return
		}

		if relay.CheckSuccess {
			// Add A/CNAME for the DNSAlias assigned
			err = addDNSRecord(targetDomainAlias, topmost, ctx.nameZoneID)
			if err != nil {
				return
			}
			fmt.Printf("[%d] Added DNS Record: %s -> %s\n", relay.ID, targetDomainAlias, topmost)

			// Update our state
			names = append(names, targetDomainAlias)
			topmost = targetDomainAlias
		} else {
			// remove entry.
			err = deleteDNSRecord(targetDomainAlias, topmost, ctx.nameZoneID)
			if err != nil {
				return
			}
			fmt.Printf("[%d] Removed DNS Record: %s -> %s\n", relay.ID, targetDomainAlias, topmost)
		}
	} else if !relay.CheckSuccess {
		// remove entry.
		err = deleteDNSRecord(targetDomainAlias, names[0], ctx.nameZoneID)
		if err != nil {
			return
		}
		fmt.Printf("[%d] Removed DNS Record: %s -> %s\n", relay.ID, targetDomainAlias, names[0])
	}

	var ensureEntry = func(use string, entries map[string]uint16, port uint16) (matchingEntries int, err error) {
		type srvMatch struct {
			name string
			port uint16
		}

		// Now check for SRV entries for anything in that chain
		var matches []srvMatch
		for _, name := range names {
			entry, has := entries[name]
			if has {
				matches = append(matches, srvMatch{name, entry})
			}
		}

		if len(matches) == 0 {
			return 0, fmt.Errorf("no %s SRV entries found mapping to %s in '%s'", use, target, srvDomain)
		}

		if len(matches) > 1 {
			return len(matches), fmt.Errorf("multiple %s SRV entries found in the chain mapping to %s", use, target)
		}

		if matches[0].name != topmost || matches[0].port != port {
			return len(matches), fmt.Errorf("existing %s SRV record mapped to intermediate DNS name or wrong port (wanted %s:%d, found %s:%d)",
				use, topmost, port, matches[0].name, matches[0].port)
		}
		return len(matches), nil
	}

	var matchCount int
	matchCount, err = ensureEntry("algobootstrap", ctx.bootstrap.entries, port)
	if relay.CheckSuccess {
		if err != nil {
			if checkOnly {
				return
			}

			// Add SRV entry to map to our DNSAlias
			err = addSRVRecord(ctx.bootstrap.networkName, topmost, port, ctx.bootstrap.shortName, ctx.srvZoneID)
			if err != nil {
				return
			}
			fmt.Printf("[%d] Added bootstrap SRV Record: %s:%d\n", relay.ID, targetDomainAlias, port)
		}
	} else {
		if matchCount > 0 {
			err = clearSRVRecord(ctx.bootstrap.networkName, topmost, ctx.bootstrap.shortName, ctx.srvZoneID)
			if err != nil {
				return
			}
			fmt.Printf("[%d] Removed bootstrap SRV Record: %s\n", relay.ID, targetDomainAlias)
		}
	}

	matchCount, err = ensureEntry("metrics", ctx.metrics.entries, metricsPort)
	if relay.MetricsEnabled {
		if relay.CheckSuccess {
			if err != nil {
				if checkOnly {
					return
				}

				// Add SRV entry for metrics
				err = addSRVRecord(ctx.metrics.networkName, topmost, metricsPort, ctx.metrics.shortName, ctx.srvZoneID)
				if err != nil {
					return
				}
				fmt.Printf("[%d] Added metrics SRV Record: %s:%d\n", relay.ID, targetDomainAlias, metricsPort)
			}
		} else {
			if matchCount > 0 {
				// metrics are enabled, but we should delete the entry since it failed the success test.
				err = clearSRVRecord(ctx.metrics.networkName, topmost, ctx.metrics.shortName, ctx.srvZoneID)
				if err != nil {
					return
				}
				fmt.Printf("[%d] Removed metrics SRV Record: %s\n", relay.ID, targetDomainAlias)
			} else {
				err = nil
			}
		}
	} else if err == nil {
		if checkOnly {
			err = fmt.Errorf("metrics should not be registered for %s but it is", target)
			return
		}
		if matchCount > 0 {
			// delete the metric entry.
			err = clearSRVRecord(ctx.metrics.networkName, topmost, ctx.metrics.shortName, ctx.srvZoneID)
			if err != nil {
				return
			}
			fmt.Printf("[%d] Removed metrics SRV Record: %s\n", relay.ID, targetDomainAlias)
		}
	} else {
		// If metrics are not enabled, then we SHOULD get an error.
		// Since this isn't actually an error, reset to nil
		err = nil
	}

	srvName = topmost
	srvPort = port
	return
}

// Returns an array of names starting with the target ip/name and ending with the outermost reference
func getTargetDNSChain(nameEntries map[string]string, target string) (names []string, err error) {
	target = strings.ToLower(target)

	names = append(names, target)
	for {
		from, has := nameEntries[target]
		if !has {
			return
		}
		names = append(names, from)
		target = from
	}
}

func getReverseMappedEntries(nameZoneID string, recordTypes []string) (reverseMap map[string]string, err error) {
	reverseMap = make(map[string]string)

	cloudflareDNS := cloudflare.NewDNS(nameZoneID, cfToken)

	for _, recType := range recordTypes {
		var records []cloudflare.DNSRecordResponseEntry
		records, err = cloudflareDNS.ListDNSRecord(context.Background(), recType, "", "", "", "", "")
		if err != nil {
			return
		}

		for _, record := range records {
			// Error if duplicates found
			from := strings.ToLower(record.Name)
			target := strings.ToLower(record.Content)
			if existing, has := reverseMap[target]; has {
				err = fmt.Errorf("duplicate NAME entries mapped to %s: (%s && %s)", target, from, existing)
				return
			}
			reverseMap[target] = from
		}
	}
	return
}

func getSrvRecords(serviceName string, networkName, zoneID string) (service srvService, err error) {
	service = makeService(serviceName, networkName)

	cloudflareDNS := cloudflare.NewDNS(zoneID, cfToken)

	var records []cloudflare.DNSRecordResponseEntry
	records, err = cloudflareDNS.ListDNSRecord(context.Background(), "SRV", service.serviceName, "", "", "", "")
	if err != nil {
		return
	}

	for _, record := range records {
		// record.Content is "priority port dnsname"
		contents := strings.Split(record.Content, "\t")
		target := strings.ToLower(contents[2])
		target = strings.TrimRight(target, ".")
		portString := contents[1]
		var port64 uint64
		port64, err = strconv.ParseUint(portString, 10, 16)
		if err != nil {
			panic(makeExitError(1, fmt.Sprintf("Invalid SRV Port for %s: %s", target, portString)))
		}
		port := uint16(port64)

		// Error if duplicates found
		if existing, has := service.entries[target]; has {
			err = fmt.Errorf("duplicate SRV entries mapped to %s: (%d && %d)", target, port, existing)
			return
		}
		service.entries[target] = port
	}
	return
}

func addDNSRecord(from string, to string, cfZoneID string) error {
	cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfToken)

	const priority = 1
	const proxied = false

	// If we need to register anything, first register a DNS entry
	// to map our network DNS name to our public name (or IP) provided to nodecfg
	// Network HostName = eg r1.testnet.algorand.network
	isIP := net.ParseIP(to) != nil
	var recordType string
	if isIP {
		recordType = "A"
	} else {
		recordType = "CNAME"
	}
	return cloudflareDNS.SetDNSRecord(context.Background(), recordType, from, to, cloudflare.AutomaticTTL, priority, proxied)
}

func addSRVRecord(srvNetwork string, target string, port uint16, serviceShortName string, cfZoneID string) error {
	cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfToken)

	const priority = 1
	const weight = 1

	return cloudflareDNS.SetSRVRecord(context.Background(), srvNetwork, target, cloudflare.AutomaticTTL, priority, uint(port), serviceShortName, "_tcp", weight)
}

func clearSRVRecord(srvNetwork string, target string, serviceShortName string, cfZoneID string) error {
	cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfToken)
	return cloudflareDNS.ClearSRVRecord(context.Background(), srvNetwork, target, serviceShortName, "_tcp")
}

func deleteDNSRecord(from string, to string, cfZoneID string) (err error) {
	isIP := net.ParseIP(to) != nil
	var recordType string
	if isIP {
		recordType = "A"
	} else {
		recordType = "CNAME"
	}

	cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfToken)

	var records []cloudflare.DNSRecordResponseEntry
	records, err = cloudflareDNS.ListDNSRecord(context.Background(), recordType, "", "", "", "", "")
	if err != nil {
		return
	}

	for _, record := range records {
		// Error if duplicates found
		recordFrom := strings.ToLower(record.Name)
		recordTarget := strings.ToLower(record.Content)
		if from == recordFrom && recordTarget == to {
			// delete the entry
			err = cloudflareDNS.DeleteDNSRecord(context.Background(), record.ID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
