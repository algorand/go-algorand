package main

import (
	"context"
	"fmt"
	"github.com/algorand/go-algorand/cmd/algorelay/eb"
	"github.com/algorand/go-algorand/tools/network/cloudflare"
	"github.com/algorand/go-algorand/util/codecs"
	"github.com/spf13/cobra"
	"net"
	"os"
	"strconv"
	"strings"
)

var (
	inputFileArg    string
	outputFileArg   string
	srvDomainArg    string
	nameDomainArg   string
	defaultPortArg  uint16
	dnsBootstrapArg string
	recordIDArg     int64

	cfEmail         string
	cfAuthKey       string
	cfSrvZoneID     string
	cfNameZoneID    string
)

var nameRecordTypes = []string{"A", "CNAME", "SRV"}
var srvRecordTypes = []string{"SRV"}

const metricsPort = uint16(9100)

func init() {
	cfSrvZoneID = os.Getenv("CLOUDFLARE_SRV_ZONE_ID")
	cfNameZoneID = os.Getenv("CLOUDFLARE_NAME_ZONE_ID")
	cfEmail = os.Getenv("CLOUDFLARE_EMAIL")
	cfAuthKey = os.Getenv("CLOUDFLARE_AUTH_KEY")
	if cfSrvZoneID == "" || cfNameZoneID == "" || cfEmail == "" || cfAuthKey == "" {
		panic("One or more credentials missing from ENV")
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
}

func loadRelays(file string) []eb.Relay {
	var relays []eb.Relay
	err := codecs.LoadObjectFromFile(file, &relays)
	if err != nil {
		panic(err)
	}
	return relays
}

type checkResult struct {
	ID        int64
	Success   bool
	Error     string  `json:",omitempty"`
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check status of all relays",
	Run: func(cmd *cobra.Command, args []string) {
		relays := loadRelays(inputFileArg)

		nameEntries, err := getReverseMappedEntries(cfNameZoneID, nameRecordTypes)
		if err != nil {
			panic(err)
		}

		bootstrapSrvService := "_algobootstrap._tcp." + dnsBootstrapArg + "." + srvDomainArg
		srvEntries, err := getSrvRecords(cfSrvZoneID, bootstrapSrvService)
		if err != nil {
			panic(err)
		}

		metricsSrvService := "_metrics._tcp." + srvDomainArg
		metricsEntries, err := getSrvRecords(cfSrvZoneID, metricsSrvService)
		if err != nil {
			panic(err)
		}

		checkOne := recordIDArg != 0
		results := make([]checkResult,0)
		anyCheckError := false

		for _, relay := range relays {
			if checkOne && relay.ID != recordIDArg {
				continue
			}

			name, port, err := verifyRelayStatus(relay, nameDomainArg, srvDomainArg, defaultPortArg, nameEntries, srvEntries, metricsEntries)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%d] ERROR: %s: %s\n", relay.ID, relay.IPOrDNSName, err)
				results = append(results, checkResult{
					ID: relay.ID,
					Success: false,
					Error: err.Error(),
					})
				anyCheckError = true
			} else {
				fmt.Printf("[%d] OK: %s -> %s:%d\n", relay.ID, relay.IPOrDNSName, name, port)
				results = append(results, checkResult{
					ID: relay.ID,
					Success: true,
				})
			}

			if checkOne {
				break
			}
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

func verifyRelayStatus(relay eb.Relay, nameDomain string, srvDomain string, defaultPort uint16, nameEntries map[string]string, srvEntries map[string]uint16, metricsEntries map[string]uint16) (srvName string, srvPort uint16, err error) {
	var port uint16
	target, portString, err := net.SplitHostPort(relay.IPOrDNSName)
	if err != nil {
		target = relay.IPOrDNSName
		port = defaultPort
	} else {
		var port64 uint64
		port64, err = strconv.ParseUint(portString, 10, 16)
		if err != nil {
			return
		}
		port = uint16(port64)
	}

	if port == 0 {
		err = fmt.Errorf("%s - port cannot be zero", relay.IPOrDNSName)
		return
	}

	// Error if target has another name entry - target should be relay provider's domain so shouldn't be possible
	if mapsTo, has := nameEntries[target]; has {
		err = fmt.Errorf("relay target has a DNS Name entry and should not (%s -> %s)", target, mapsTo)
	}

	names, err := getTargetDNSChain(nameEntries, target)
	if err != nil {
		return
	}

	// Error if no entries
	if len(names) == 1 {
		err = fmt.Errorf("no DNS entries found mapping to %s in '%s'", target, nameDomain)
		return
	}

	topmost := names[len(names)-1]

	if topmost != relay.DNSAlias+"."+nameDomain {
		err = fmt.Errorf("topmost DNS name is not the assigned DNS Alias (wanted: %s, found %s)",
			relay.DNSAlias, topmost)
		return
	}

	var ensureEntry = func(use string, entries map[string]uint16, port uint16) error {
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
			return fmt.Errorf("no %s SRV entries found mapping to %s in '%s'", use, target, srvDomain)
		}

		if len(matches) > 1 {
			return fmt.Errorf("multiple %s SRV entries found in the chain mapping to %s", use, target)
		}

		if matches[0].name != topmost || matches[0].port != port {
			return fmt.Errorf("existing %s SRV record mapped to intermediate DNS name or wrong port (wanted %s:%d, found %s:%d)",
				use, topmost, port, matches[0].name, matches[0].port)
		}
		return nil
	}

	err = ensureEntry("bootstrap", srvEntries, port)
	if err != nil {
		return
	}

	err = ensureEntry("metrics", metricsEntries, metricsPort)
	if relay.MetricsEnabled {
		if err != nil {
			return
		}
	} else if err == nil {
		err = fmt.Errorf("metrics should not be registered for %s but it is", target)
	}

	srvName = topmost
	srvPort = port
	return
}

// Returns an array of names starting with the target ip/name and ending with the outermost reference
func getTargetDNSChain(nameEntries map[string]string, target string) (names []string, err error) {
	target = strings.ToLower(target)
	if err != nil {
		return
	}

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

func getReverseMappedEntries(zoneID string, recordTypes []string) (reverseMap map[string]string, err error) {
	reverseMap = make(map[string]string)

	cloudflareDNS := cloudflare.NewDNS(zoneID, cfEmail, cfAuthKey)

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

func getSrvRecords(zoneID string, serviceName string) (srvEntries map[string]uint16, err error){
	srvEntries = make(map[string]uint16)

	cloudflareDNS := cloudflare.NewDNS(zoneID, cfEmail, cfAuthKey)

	var records []cloudflare.DNSRecordResponseEntry
	records, err = cloudflareDNS.ListDNSRecord(context.Background(), "SRV", serviceName, "", "", "", "")
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
			panic(fmt.Sprintf("Invalid SRV Port for %s: %s", target, portString))
		}
		port := uint16(port64)

		// Error if duplicates found
		if existing, has := srvEntries[target]; has {
			err = fmt.Errorf("duplicate SRV entries mapped to %s: (%d && %d)", target, port, existing)
			return
		}
		srvEntries[target] = port
	}
	return
}

//var addCmd = &cobra.Command{
//	Use:   "add",
//	Short: "Add a DNS record",
//	Long:  "Adds a DNS record to map --from to --to, using A if to == IP or CNAME otherwise\n",
//	Example: "algons dns add -f a.test.algodev.network -t r1.algodev.network\n" +
//		"algons dns add -f a.test.algodev.network -t 192.168.100.10",
//	Run: func(cmd *cobra.Command, args []string) {
//		err := doAddDNS(addFromName, addToAddress)
//		if err != nil {
//			fmt.Fprintf(os.Stderr, "Error adding DNS entry: %v\n", err)
//			os.Exit(1)
//		} else {
//			fmt.Printf("DNS Entry Added\n")
//		}
//	},
//}
//
//var deleteCmd = &cobra.Command{
//	Use:   "delete",
//	Short: "Delete DNS and SRV records for a specified network",
//	Run: func(cmd *cobra.Command, args []string) {
//		if !doDeleteDNS(deleteNetwork, noPrompt, excludePattern) {
//			os.Exit(1)
//		}
//	},
//}
//
//func doAddDNS(from string, to string) (err error) {
//	cfZoneID, cfEmail, cfKey, err := getClouldflareCredentials()
//	if err != nil {
//		return fmt.Errorf("error getting DNS credentials: %v", err)
//	}
//
//	cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfEmail, cfKey)
//
//	const priority = 1
//	const proxied = false
//
//	// If we need to register anything, first register a DNS entry
//	// to map our network DNS name to our public name (or IP) provided to nodecfg
//	// Network HostName = eg r1.testnet.algorand.network
//	isIP := net.ParseIP(to) != nil
//	var recordType string
//	if isIP {
//		recordType = "A"
//	} else {
//		recordType = "CNAME"
//	}
//	cloudflareDNS.SetDNSRecord(context.Background(), recordType, from, to, cloudflare.AutomaticTTL, priority, proxied)
//
//	return
//}

//func checkDNSRecord(dnsName string) {
//	fmt.Printf("------------------------\nDNS Lookup: %s\n", dnsName)
//	ips, err := net.LookupIP(dnsName)
//	if err != nil {
//		fmt.Printf("Cannot resolve %s: %v\n", dnsName, err)
//	} else {
//		sort.Sort(byIP(ips))
//		for _, ip := range ips {
//			fmt.Printf("-> %s\n", ip.String())
//		}
//	}
//}
//
//func doDeleteDNS(network string, noPrompt bool, excludePattern string) bool {
//
//	if network == "" || network == "testnet" || network == "devnet" || network == "mainnet" {
//		fmt.Fprintf(os.Stderr, "Deletion of network '%s' using this tool is not allowed\n", network)
//		return false
//	}
//
//	var excludeRegex *regexp.Regexp
//	if excludePattern != "" {
//		var err error
//		excludeRegex, err = regexp.Compile(excludePattern)
//		if err != nil {
//			fmt.Fprintf(os.Stderr, "specified regular expression exclude pattern ('%s') is not a valid regular expression : %v", excludePattern, err)
//			return false
//		}
//	}
//
//	cfZoneID, cfEmail, cfKey, err := getClouldflareCredentials()
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "error getting DNS credentials: %v", err)
//		return false
//	}
//
//	cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfEmail, cfKey)
//
//	idsToDelete := make(map[string]string) // Maps record ID to Name
//
//	for _, service := range []string{"_algobootstrap", "_metrics"} {
//		records, err := cloudflareDNS.ListDNSRecord(context.Background(), "SRV", service+"._tcp."+network+".algodev.network", "", "", "", "")
//		if err != nil {
//			fmt.Fprintf(os.Stderr, "Error listing SRV '%s' entries: %v\n", service, err)
//			os.Exit(1)
//		}
//		for _, r := range records {
//			if excludeRegex != nil {
//				if excludeRegex.MatchString(r.Name) {
//					fmt.Printf("Excluding SRV '%s' record: %s\n", service, r.Name)
//					continue
//				}
//			}
//			fmt.Printf("Found SRV '%s' record: %s\n", service, r.Name)
//			idsToDelete[r.ID] = r.Name
//		}
//	}
//
//	networkSuffix := "." + network + ".algodev.network"
//
//	for _, recordType := range []string{"A", "CNAME"} {
//		records, err := cloudflareDNS.ListDNSRecord(context.Background(), recordType, "", "", "", "", "")
//		if err != nil {
//			fmt.Fprintf(os.Stderr, "Error listing DNS '%s' entries: %v\n", recordType, err)
//			os.Exit(1)
//		}
//		for _, r := range records {
//			if strings.Index(r.Name, networkSuffix) > 0 {
//				if excludeRegex != nil {
//					if excludeRegex.MatchString(r.Name) {
//						fmt.Printf("Excluding DNS '%s' record: %s\n", recordType, r.Name)
//						continue
//					}
//				}
//				fmt.Printf("Found DNS '%s' record: %s\n", recordType, r.Name)
//				idsToDelete[r.ID] = r.Name
//			}
//		}
//	}
//
//	if len(idsToDelete) == 0 {
//		fmt.Printf("No DNS/SRV records found\n")
//		return true
//	}
//
//	var text string
//	if !noPrompt {
//		reader := bufio.NewReader(os.Stdin)
//		fmt.Printf("Delete these %d entries (type 'yes' to delete)? ", len(idsToDelete))
//		text, _ = reader.ReadString('\n')
//		text = strings.Replace(text, "\n", "", -1)
//	} else {
//		text = "yes"
//	}
//
//	if text == "yes" {
//		for id, name := range idsToDelete {
//			fmt.Fprintf(os.Stdout, "Deleting %s\n", name)
//			err = cloudflareDNS.DeleteDNSRecord(context.Background(), id)
//			if err != nil {
//				fmt.Fprintf(os.Stderr, " !! error deleting %s: %v\n", name, err)
//			}
//		}
//	}
//	return true
//}
//
