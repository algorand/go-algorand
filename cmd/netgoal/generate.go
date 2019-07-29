// Copyright (C) 2019 Algorand, Inc.
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
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/util/codecs"
)

var outputFilename string
var templateToGenerate string
var relaysToGenerate int
var nodesToGenerate int
var nodeHostsToGenerate int
var walletsToGenerate int
var nodeTemplatePath string
var relayTemplatePath string

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&outputFilename, "outputfile", "o", "", "Output filename")
	generateCmd.MarkFlagRequired("outputfile")

	generateCmd.Flags().StringVarP(&templateToGenerate, "template", "t", "", "Template to generate")

	generateCmd.Flags().IntVarP(&walletsToGenerate, "wallets", "w", -1, "Wallets to generate")
	generateCmd.Flags().IntVarP(&relaysToGenerate, "relays", "R", -1, "Relays to generate")
	generateCmd.Flags().IntVarP(&nodeHostsToGenerate, "node-hosts", "N", -1, "Node-hosts to generate, default=nodes")
	generateCmd.Flags().IntVarP(&nodesToGenerate, "nodes", "n", -1, "Nodes to generate")
	generateCmd.Flags().StringVarP(&nodeTemplatePath, "node-template", "", "", "json for one node")
	generateCmd.Flags().StringVarP(&relayTemplatePath, "relay-template", "", "", "json for a relay node")

	longParts := make([]string, len(generateTemplateLines)+1)
	longParts[0] = generateCmd.Long
	copy(longParts[1:], generateTemplateLines)
	generateCmd.Long = strings.Join(longParts, "\n")
}

var generateTemplateLines = []string{
	"net => network template according to -R -N -n -w options",
	"genesis => genesis.json according to -w option",
	"otwt => OneThousandWallets network template",
	"otwg => OneThousandWallets genesis data",
	"ohwg => OneHundredWallets genesis data",
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "generate network template",
	Long: `generate network template or genesis.json
-r is required for all netgoal commands but unused by generate

template modes for -t:`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		baseNode := remote.NodeConfig{}
		baseRelay := remote.NodeConfig{}
		if nodeTemplatePath != "" {
			fin, err := os.Open(nodeTemplatePath)
			if err != nil {
				reportErrorf("%s: bad node template, %s", nodeTemplatePath, err)
			}
			dec := json.NewDecoder(fin)
			err = dec.Decode(&baseNode)
			if err != nil {
				reportErrorf("%s: bad node template, %s", nodeTemplatePath, err)
			}
		}
		if relayTemplatePath != "" {
			fin, err := os.Open(relayTemplatePath)
			if err != nil {
				reportErrorf("%s: bad relay template, %s", relayTemplatePath, err)
			}
			dec := json.NewDecoder(fin)
			err = dec.Decode(&baseRelay)
			if err != nil {
				reportErrorf("%s: bad relay template, %s", relayTemplatePath, err)
			}
		} else {
			baseRelay = baseNode
		}
		switch strings.ToLower(templateToGenerate) {
		case "genesis", "wallets":
			if walletsToGenerate < 0 {
				reportErrorf("must specify number of wallets with -w")
			}
			err = generateWalletGenesis(outputFilename, walletsToGenerate)
		case "net", "network":
			if walletsToGenerate < 0 {
				reportErrorf("must specify number of wallets with -w")
			}
			if nodesToGenerate < 0 {
				reportErrorf("must specify number of nodes with -n")
			}
			if nodeHostsToGenerate < 0 {
				nodeHostsToGenerate = nodesToGenerate
			}
			if relaysToGenerate < 0 {
				reportErrorf("must specify number of relays with -R")
			}

			err = generateNetworkTemplate(outputFilename, walletsToGenerate, relaysToGenerate, nodeHostsToGenerate, nodesToGenerate, baseNode, baseRelay)
		case "otwt":
			err = generateNetworkTemplate(outputFilename, 1000, 10, 20, 100, baseNode, baseRelay)
		case "otwg":
			err = generateWalletGenesis(outputFilename, 1000)
		case "ohwg":
			err = generateWalletGenesis(outputFilename, 100)
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

func generateNetworkTemplate(templateFilename string, wallets, relays, nodeHosts, nodes int, baseNode, baseRelay remote.NodeConfig) error {
	network := remote.DeployedNetworkConfig{}

	relayTemplates := unpackNodeConfig(baseRelay)
	leafTemplates := unpackNodeConfig(baseNode)

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

	walletIndex := 0
	for walletIndex < wallets {
		for hosti := range network.Hosts {
			for nodei, node := range network.Hosts[hosti].Nodes {
				if node.Name[0:5] == "relay" {
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

func generateWalletGenesis(filename string, wallets int) error {
	data := gen.DefaultGenesis
	data.Wallets = make([]gen.WalletData, wallets)
	stake := 100.0 / float64(wallets)

	stakeSum := float64(0)
	for i := 0; i < wallets; i++ {
		if i == (wallets - 1) {
			// use the last wallet to workaround roundoff and get back to 1.0
			stake = 100.0 - stakeSum
		}
		w := gen.WalletData{
			Name:   "Wallet" + strconv.Itoa(i+1), // Wallet names are 1-based for this template
			Stake:  stake,
			Online: true,
		}
		stakeSum += stake
		data.Wallets[i] = w
	}
	return saveGenesisDataToDisk(data, filename)
}

func saveGenesisDataToDisk(genesisData gen.GenesisData, filename string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		defer f.Close()

		enc := codecs.NewFormattedJSONEncoder(f)
		err = enc.Encode(genesisData)
	}
	return err
}
