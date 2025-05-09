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
	"encoding/json"
	"errors"
	"math/big"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/netdeploy"
	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/util/codecs"
)

var outputFilename string
var templateToGenerate string
var relaysToGenerate int
var participationAlgodNodes int
var participationHostMachines int
var npnAlgodNodes int
var npnHostMachines int
var walletsToGenerate int
var nodeTemplatePath string
var nonParticipatingNodeTemplatePath string
var relayTemplatePath string
var sourceWallet string
var rounds uint64
var roundTxnCount uint64
var accountsCount uint64
var assetsCount uint64
var applicationCount uint64
var balRange []string
var lastPartKeyRound uint64
var deterministicKeys bool

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&outputFilename, "outputfile", "o", "", "Output filename")
	generateCmd.MarkFlagRequired("outputfile")

	generateCmd.Flags().StringVarP(&templateToGenerate, "template", "t", "", "Template to generate")

	generateCmd.Flags().IntVarP(&walletsToGenerate, "wallets", "w", -1, "Wallets to generate")
	generateCmd.Flags().IntVarP(&relaysToGenerate, "relays", "R", -1, "Relays to generate")
	generateCmd.Flags().IntVarP(&participationAlgodNodes, "participation-algod-nodes", "n", -1, "Total participation algod nodes to generate")
	generateCmd.Flags().IntVarP(&participationHostMachines, "participation-host-machines", "N", -1, "Host machines to generate for participation algod nodes, default=participation-algod-nodes")
	generateCmd.Flags().IntVarP(&npnAlgodNodes, "npn-algod-nodes", "x", 0, "Total non-participation algod nodes to generate")
	generateCmd.Flags().IntVarP(&npnHostMachines, "npn-host-machines", "X", 0, "Host machines to generate for non-participation algod nodes, default=npn-algod-nodes")
	generateCmd.Flags().StringVarP(&nodeTemplatePath, "node-template", "", "", "json for one node")
	generateCmd.Flags().StringVarP(&nonParticipatingNodeTemplatePath, "non-participating-node-template", "", "", "json for non participating node")
	generateCmd.Flags().StringVarP(&relayTemplatePath, "relay-template", "", "", "json for a relay node")
	generateCmd.Flags().StringVarP(&sourceWallet, "wallet-name", "", "", "Source wallet name")
	generateCmd.Flags().Uint64VarP(&rounds, "rounds", "", 13, "Number of rounds")
	generateCmd.Flags().Uint64VarP(&roundTxnCount, "ntxns", "", 17, "Transaction count")
	generateCmd.Flags().Uint64VarP(&accountsCount, "naccounts", "", 31, "Account count")
	generateCmd.Flags().Uint64VarP(&assetsCount, "nassets", "", 5, "Asset count")
	generateCmd.Flags().Uint64VarP(&applicationCount, "napps", "", 7, "Application Count")
	generateCmd.Flags().StringArrayVar(&balRange, "bal", []string{}, "Application Count")
	generateCmd.Flags().BoolVarP(&deterministicKeys, "deterministic", "", false, "Whether to generate deterministic keys")
	generateCmd.Flags().Uint64VarP(&lastPartKeyRound, "last-part-key-round", "", gen.DefaultGenesis.LastPartKeyRound, "LastPartKeyRound in genesis.json")

	longParts := make([]string, len(generateTemplateLines)+1)
	longParts[0] = generateCmd.Long
	copy(longParts[1:], generateTemplateLines)
	generateCmd.Long = strings.Join(longParts, "\n")
}

var generateTemplateLines = []string{
	"net => network template according to -R -N -n -w options. Suitable for 'netgoal build'",
	"goalnet => goal network template according to -R -n -w options. Suitable for 'goal network'",
	"genesis => genesis.json according to -w option",
	"otwt => OneThousandWallets network template",
	"otwg => OneThousandWallets genesis data",
	"ohwg => OneHundredWallets genesis data",
	"loadingFile => create accounts database file according to -wallet-name -rounds -ntxns -naccts -nassets -napps options",
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate network template",
	Long: `Generate network template or genesis.json
-r is required for all netgoal commands but unused by generate

template modes for -t:`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		baseNode := remote.NodeConfig{}
		baseRelay := remote.NodeConfig{}
		baseNonParticipatingNode := remote.NodeConfig{}
		if nodeTemplatePath != "" {
			fin, err1 := os.Open(nodeTemplatePath)
			if err1 != nil {
				reportErrorf("%s: bad node template, %s", nodeTemplatePath, err1)
			}
			dec := json.NewDecoder(fin)
			err1 = dec.Decode(&baseNode)
			if err1 != nil {
				reportErrorf("%s: bad node template, %s", nodeTemplatePath, err1)
			}
		}
		if nonParticipatingNodeTemplatePath != "" {
			fin, err1 := os.Open(nonParticipatingNodeTemplatePath)
			if err1 != nil {
				reportErrorf("%s: bad npnode template, %s", nonParticipatingNodeTemplatePath, err1)
			}
			dec := json.NewDecoder(fin)
			err1 = dec.Decode(&baseNonParticipatingNode)
			if err1 != nil {
				reportErrorf("%s: bad node template, %s", nodeTemplatePath, err1)
			}
		} else {
			baseNonParticipatingNode = baseNode
		}
		if relayTemplatePath != "" {
			fin, err1 := os.Open(relayTemplatePath)
			if err1 != nil {
				reportErrorf("%s: bad relay template, %s", relayTemplatePath, err1)
			}
			dec := json.NewDecoder(fin)
			err1 = dec.Decode(&baseRelay)
			if err1 != nil {
				reportErrorf("%s: bad relay template, %s", relayTemplatePath, err1)
			}
		} else {
			baseRelay = baseNode
		}
		templateType := strings.ToLower(templateToGenerate)
		switch templateType {
		case "genesis", "wallets":
			if walletsToGenerate < 0 {
				reportErrorf("must specify number of wallets with -w")
			}
			err = generateWalletGenesis(outputFilename, walletsToGenerate, npnAlgodNodes)
		case "net", "network", "goalnet":
			if walletsToGenerate < 0 {
				reportErrorf("must specify number of wallets with -w")
			}
			if participationAlgodNodes < 0 {
				reportErrorf("must specify number of nodes with -n")
			}
			if participationHostMachines < 0 {
				participationHostMachines = participationAlgodNodes
			}
			if (npnAlgodNodes >= 0) && (npnHostMachines == 0) {
				npnHostMachines = npnAlgodNodes
			}
			if relaysToGenerate < 0 {
				reportErrorf("must specify number of relays with -R")
			}
			if templateType == "goalnet" {
				err = generateNetworkGoalTemplate(outputFilename, walletsToGenerate, relaysToGenerate, participationAlgodNodes, npnAlgodNodes)
			} else {
				err = generateNetworkTemplate(outputFilename, walletsToGenerate, relaysToGenerate, participationHostMachines, participationAlgodNodes, npnHostMachines, npnAlgodNodes, baseNode, baseNonParticipatingNode, baseRelay)
			}
		case "otwt":
			err = generateNetworkTemplate(outputFilename, 1000, 10, 20, 100, 0, 0, baseNode, baseNonParticipatingNode, baseRelay)
		case "otwg":
			err = generateWalletGenesis(outputFilename, 1000, 0)
		case "ohwg":
			err = generateWalletGenesis(outputFilename, 100, 0)
		case "loadingfile":
			if sourceWallet == "" {
				reportErrorf("must specify source wallet name with -wname.")
			}
			if len(balRange) < 2 {
				reportErrorf("must specify account balance range with --bal.")
			}
			err = generateAccountsLoadingFileTemplate(outputFilename, sourceWallet, rounds, roundTxnCount, accountsCount, assetsCount, applicationCount, balRange, deterministicKeys)
		default:
			reportInfoln("Please specify a valid template name.\nSupported templates are:")
			for _, line := range generateTemplateLines {
				reportInfof("\t%s", line)
			}
			return
		}
		if err != nil {
			reportErrorf("error generating template file: %v\n", err)
		}
	},
}

func unpackNodeConfig(base remote.NodeConfig) []remote.NodeConfig {
	out := make([]remote.NodeConfig, 1+len(base.AltConfigs))
	out[0] = base
	if len(base.AltConfigs) > 0 {
		for i, ac := range base.AltConfigs {
			out[i+1] = ac
		}
	}
	out[0].AltConfigs = nil
	return out
}

func pickNodeConfig(alt []remote.NodeConfig, name string) remote.NodeConfig {
	psum := float64(0.0)
	for _, cfg := range alt {
		if cfg.NodeNameMatchRegex != "" {
			if match, _ := regexp.MatchString(cfg.NodeNameMatchRegex, name); match {
				return cfg
			}
		}
		psum += cfg.FractionApply
	}
	if psum > 0.0 {
		if psum < 1.0 {
			// the remaining fraction will be applied to the default config at alt[0] when the sum doesn't rise above psum
			psum = 1.0
		}
		hit := rand.Float64() * psum
		sofar := float64(0.0)
		for _, cfg := range alt {
			sofar += cfg.FractionApply
			if sofar > hit {
				return cfg
			}
		}
	}
	return alt[0]
}

func generateNetworkGoalTemplate(templateFilename string, wallets, relays, nodes, npnNodes int) error {
	template := netdeploy.NetworkTemplate{}
	template.Nodes = make([]remote.NodeConfigGoal, 0, relays+nodes+npnNodes)
	template.Genesis = generateWalletGenesisData(walletsToGenerate, 0)
	for i := 0; i < relays; i++ {
		name := "relay" + strconv.Itoa(i+1)
		newNode := remote.NodeConfigGoal{
			Name:    name,
			IsRelay: true,
			Wallets: nil,
		}
		template.Nodes = append(template.Nodes, newNode)
	}

	for i := 0; i < nodes; i++ {
		name := "node" + strconv.Itoa(i+1)
		newNode := remote.NodeConfigGoal{
			Name:    name,
			Wallets: make([]remote.NodeWalletData, 0),
		}
		template.Nodes = append(template.Nodes, newNode)
	}

	for i := 0; i < npnNodes; i++ {
		name := "nonParticipatingNode" + strconv.Itoa(i+1)
		newNode := remote.NodeConfigGoal{
			Name:    name,
			Wallets: make([]remote.NodeWalletData, 0),
		}
		template.Nodes = append(template.Nodes, newNode)
	}
	walletIndex := 0
	for walletIndex < wallets {
		for nodei, node := range template.Nodes {
			if node.Name[0:4] != "node" {
				continue
			}
			wallet := remote.NodeWalletData{
				Name:              "Wallet" + strconv.Itoa(walletIndex+1),
				ParticipationOnly: false,
			}
			template.Nodes[nodei].Wallets = append(template.Nodes[nodei].Wallets, wallet)
			walletIndex++
			if walletIndex >= wallets {
				break
			}
		}
		if walletIndex >= wallets {
			break
		}
	}

	if npnNodes > 0 {
		for walletIndex < npnNodes {
			for nodei, node := range template.Nodes {
				if node.Name[0:4] != "nonP" {
					continue
				}
				wallet := remote.NodeWalletData{
					Name:              "Wallet" + strconv.Itoa(walletIndex+1),
					ParticipationOnly: false,
				}
				template.Nodes[nodei].Wallets = append(template.Nodes[nodei].Wallets, wallet)
				walletIndex++
				if walletIndex >= npnNodes {
					break
				}
			}
			if walletIndex >= npnNodes {
				break
			}
		}
	}
	return saveGoalTemplateToDisk(template, templateFilename)
}

func generateNetworkTemplate(templateFilename string, wallets, relays, nodeHosts, nodes, npnHosts, npns int, baseNode, baseNonPartNode, baseRelay remote.NodeConfig) error {
	network := remote.DeployedNetworkConfig{}

	relayTemplates := unpackNodeConfig(baseRelay)
	leafTemplates := unpackNodeConfig(baseNode)
	npnTemplates := unpackNodeConfig(baseNonPartNode)

	for i := 0; i < relays; i++ {
		indexID := strconv.Itoa(i + 1)
		host := remote.HostConfig{
			Name: "R" + indexID,
		}
		name := "relay" + indexID
		newNode := pickNodeConfig(relayTemplates, name)
		newNode.NodeNameMatchRegex = ""
		newNode.FractionApply = 0.0
		newNode.Name = name
		if newNode.NetAddress == "" {
			return errors.New("relay template did not set NetAddress")
		}
		newNode.Wallets = nil
		host.Nodes = append(host.Nodes, newNode)
		network.Hosts = append(network.Hosts, host)
	}

	for i := 0; i < nodeHosts; i++ {
		indexID := strconv.Itoa(i + 1)
		host := remote.HostConfig{
			Name: "N" + indexID,
		}
		network.Hosts = append(network.Hosts, host)
	}

	nodeIndex := 0
	for nodeIndex < nodes {
		for hosti, host := range network.Hosts {
			if host.Name[0] == 'R' {
				// don't assign user nodes to relay hosts
				continue
			}
			name := "node" + strconv.Itoa(nodeIndex+1)
			node := pickNodeConfig(leafTemplates, name)
			node.NodeNameMatchRegex = ""
			node.FractionApply = 0.0
			node.Name = name
			network.Hosts[hosti].Nodes = append(network.Hosts[hosti].Nodes, node)
			nodeIndex++
			if nodeIndex >= nodes {
				break
			}
		}
	}

	npnHostIndexes := make([]int, 0, npnHosts)
	for i := 0; i < npnHosts; i++ {
		indexID := strconv.Itoa(i + 1)

		name := "nonParticipatingNode" + strconv.Itoa(i+1)
		node := pickNodeConfig(npnTemplates, name)
		node.NodeNameMatchRegex = ""
		node.FractionApply = 0.0
		node.Name = name
		host := remote.HostConfig{
			Name:  "NPN" + indexID,
			Nodes: []remote.NodeConfig{node},
		}
		npnHostIndexes = append(npnHostIndexes, len(network.Hosts))
		network.Hosts = append(network.Hosts, host)
	}
	for i := npnHosts; i < npns; i++ {
		hosti := npnHostIndexes[i%len(npnHostIndexes)]
		name := "nonParticipatingNode" + strconv.Itoa(i+1)
		node := pickNodeConfig(npnTemplates, name)
		node.NodeNameMatchRegex = ""
		node.FractionApply = 0.0
		node.Name = name
		network.Hosts[hosti].Nodes = append(network.Hosts[hosti].Nodes, node)
	}

	walletIndex := 0
	for walletIndex < wallets {
		for hosti := range network.Hosts {
			for nodei, node := range network.Hosts[hosti].Nodes {
				if node.Name[0:4] != "node" {
					continue
				}
				wallet := remote.NodeWalletData{
					Name:              "Wallet" + strconv.Itoa(walletIndex+1),
					ParticipationOnly: false,
				}
				network.Hosts[hosti].Nodes[nodei].Wallets = append(network.Hosts[hosti].Nodes[nodei].Wallets, wallet)
				walletIndex++
				if walletIndex >= wallets {
					break
				}
			}
			if walletIndex >= wallets {
				break
			}
		}
	}

	// one wallet per NPN host to concentrate stake
	if npns > 0 {
		walletIndex := 0
		for walletIndex < npns {
			for hosti := range network.Hosts {
				for nodei, node := range network.Hosts[hosti].Nodes {
					if node.Name[0:4] != "nonP" {
						continue
					}
					wallet := remote.NodeWalletData{
						Name:              "Wallet" + strconv.Itoa(wallets+walletIndex+1),
						ParticipationOnly: false,
					}
					network.Hosts[hosti].Nodes[nodei].Wallets = append(network.Hosts[hosti].Nodes[nodei].Wallets, wallet)
					walletIndex++
					if walletIndex >= npns {
						break
					}
				}
				if walletIndex >= npns {
					break
				}
			}
		}
	}

	// ensure that at most one node per host claims any APIEndpoint port
	for hosti, host := range network.Hosts {
		seenAPIEndpoint := make(map[string]bool, 4)
		for nodei, node := range host.Nodes {
			if node.APIEndpoint != "" {
				if seenAPIEndpoint[node.APIEndpoint] {
					// squash dup
					network.Hosts[hosti].Nodes[nodei].APIEndpoint = ""
				} else {
					seenAPIEndpoint[node.APIEndpoint] = true
				}
			}
		}
	}

	return saveTemplateToDisk(network, templateFilename)
}

func saveTemplateToDisk(template remote.DeployedNetworkConfig, filename string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		defer f.Close()

		enc := codecs.NewFormattedJSONEncoder(f)
		err = enc.Encode(template)
	}
	return err
}

func saveGoalTemplateToDisk(template netdeploy.NetworkTemplate, filename string) error {
	if lastPartKeyRound != 0 {
		template.Genesis.LastPartKeyRound = lastPartKeyRound
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		defer f.Close()

		enc := codecs.NewFormattedJSONEncoder(f)
		err = enc.Encode(template)
	}
	return err
}

func generateWalletGenesisData(wallets, npnNodes int) gen.GenesisData {
	ratZero := big.NewRat(int64(0), int64(1))
	ratHundred := big.NewRat(int64(100), int64(1))
	data := gen.DefaultGenesis
	totalWallets := wallets + npnNodes
	data.Wallets = make([]gen.WalletData, totalWallets)
	participatingNodeStake := big.NewRat(int64(100), int64(wallets))
	nonParticipatingNodeStake := ratZero
	if npnNodes > 0 {
		// split participating an non participating stake evenly
		participatingNodeStake = big.NewRat(int64(50), int64(wallets))
		nonParticipatingNodeStake = big.NewRat(int64(50), int64(npnNodes))
	}

	stake := ratZero
	stakeSum := new(big.Rat).Set(ratZero)
	for i := 0; i < totalWallets; i++ {

		if i < wallets {
			stake = participatingNodeStake
		} else {
			stake = nonParticipatingNodeStake
		}
		if i == (totalWallets - 1) {
			// use the last wallet to workaround roundoff and get back to 1.0
			stake = stake.Sub(new(big.Rat).Set(ratHundred), stakeSum)
		}
		floatStake, _ := stake.Float64()
		w := gen.WalletData{
			Name:  "Wallet" + strconv.Itoa(i+1), // Wallet names are 1-based for this template
			Stake: floatStake,
		}
		if i < wallets {
			w.Online = true
		}
		stakeSum = stakeSum.Add(stakeSum, stake)
		data.Wallets[i] = w
	}
	return data
}

func generateWalletGenesis(filename string, wallets, npnNodes int) error {
	data := generateWalletGenesisData(wallets, npnNodes)
	return saveGenesisDataToDisk(data, filename)
}

func saveGenesisDataToDisk(genesisData gen.GenesisData, filename string) error {
	if lastPartKeyRound != 0 {
		genesisData.LastPartKeyRound = lastPartKeyRound
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		defer f.Close()

		enc := codecs.NewFormattedJSONEncoder(f)
		err = enc.Encode(genesisData)
	}
	return err
}

func generateAccountsLoadingFileTemplate(templateFilename, sourceWallet string, rounds, roundTxnCount, accountsCount, assetsCount, applicationCount uint64, balRange []string, deterministicKeys bool) error {

	min, err := strconv.ParseInt(balRange[0], 0, 64)
	if err != nil {
		return err
	}
	max, err := strconv.ParseInt(balRange[1], 0, 64)
	if err != nil {
		return err
	}

	var data = remote.BootstrappedNetwork{
		NumRounds:                 rounds,
		RoundTransactionsCount:    roundTxnCount,
		GeneratedAccountsCount:    accountsCount,
		GeneratedAssetsCount:      assetsCount,
		GeneratedApplicationCount: applicationCount,
		SourceWalletName:          sourceWallet,
		BalanceRange:              []int64{min, max},
		DeterministicKeys:         deterministicKeys,
	}
	return saveLoadingFileDataToDisk(data, templateFilename)
}

func saveLoadingFileDataToDisk(data remote.BootstrappedNetwork, filename string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := codecs.NewFormattedJSONEncoder(f)
	return enc.Encode(data)
}
