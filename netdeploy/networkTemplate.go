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

package netdeploy

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/util"
)

// NetworkTemplate represents the template used for creating private named networks
type NetworkTemplate struct {
	Genesis   gen.GenesisData
	Nodes     []remote.NodeConfigGoal
	Consensus config.ConsensusProtocols
}

var defaultNetworkTemplate = NetworkTemplate{
	Genesis: gen.DefaultGenesis,
}

func (t NetworkTemplate) generateGenesisAndWallets(targetFolder, networkName, binDir string) error {
	genesisData := t.Genesis
	genesisData.NetworkName = networkName
	mergedConsensus := config.Consensus.Merge(t.Consensus)
	return gen.GenerateGenesisFiles(genesisData, mergedConsensus, targetFolder, true)
}

// Create data folders for all NodeConfigs, configuring relays appropriately and
// returning the full path to the 'prime' relay and node folders (the first one created) and the genesis data used in this network.
func (t NetworkTemplate) createNodeDirectories(targetFolder string, binDir string, importKeys bool) (relayDirs []string, nodeDirs map[string]string, genData gen.GenesisData, err error) {
	genesisFile := filepath.Join(targetFolder, genesisFileName)
	genData, err = gen.LoadGenesisData(genesisFile)
	if err != nil {
		return
	}

	nodeDirs = make(map[string]string)
	getGenesisVerCmd := filepath.Join(binDir, "algod")
	importKeysCmd := filepath.Join(binDir, "goal")
	genesisVer, _, err := util.ExecAndCaptureOutput(getGenesisVerCmd, "-G", "-d", targetFolder)
	if err != nil {
		return
	}
	genesisVer = strings.TrimSpace(genesisVer)

	for _, cfg := range t.Nodes {
		nodeDir := filepath.Join(targetFolder, cfg.Name)
		err = os.Mkdir(nodeDir, os.ModePerm)
		if err != nil {
			return
		}

		_, err = util.CopyFile(genesisFile, filepath.Join(nodeDir, genesisFileName))
		if err != nil {
			return
		}

		if cfg.IsRelay {
			_, err = filepath.Abs(nodeDir)
			if err != nil {
				return
			}
			relayDirs = append(relayDirs, cfg.Name)
		} else {
			nodeDirs[cfg.Name] = cfg.Name
		}

		genesisDir := filepath.Join(nodeDir, genesisVer)
		err = os.Mkdir(genesisDir, os.ModePerm)
		if err != nil {
			return
		}

		var files []os.FileInfo
		files, err = ioutil.ReadDir(targetFolder)
		if err != nil {
			return
		}

		hasWallet := false
		for _, info := range files {
			name := info.Name()
			if config.IsRootKeyFilename(name) || config.IsPartKeyFilename(name) {
				for _, wallet := range cfg.Wallets {
					if (config.MatchesRootKeyFilename(wallet.Name, name) && !wallet.ParticipationOnly) || config.MatchesPartKeyFilename(wallet.Name, name) {
						// fmt.Println("cp", filepath.Join(targetFolder, name), "->", filepath.Join(genesisDir, name))
						_, err = util.CopyFile(filepath.Join(targetFolder, name), filepath.Join(genesisDir, name))
						if err != nil {
							return
						}
						hasWallet = true
					}
				}
			}
		}

		if importKeys && hasWallet {
			var client libgoal.Client
			client, err = libgoal.MakeClientWithBinDir(binDir, nodeDir, "", libgoal.KmdClient)
			_, err = client.CreateWallet(libgoal.UnencryptedWalletName, nil, crypto.MasterDerivationKey{})
			if err != nil {
				return
			}

			_, _, err = util.ExecAndCaptureOutput(importKeysCmd, "account", "importrootkey", "-w", string(libgoal.UnencryptedWalletName), "-d", nodeDir)
			if err != nil {
				return
			}
		}

		// Create any necessary config.json file for this node
		nodeCfg := filepath.Join(nodeDir, config.ConfigFilename)
		err = createConfigFile(cfg, nodeCfg, len(t.Nodes)-1) // minus 1 to avoid counting self
		if err != nil {
			return
		}
	}
	return
}

func loadTemplate(templateFile string) (NetworkTemplate, error) {
	template := defaultNetworkTemplate
	f, err := os.Open(templateFile)
	if err != nil {
		return template, err
	}
	defer f.Close()

	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		// for arm machines, use smaller key dilution
		template.Genesis.PartKeyDilution = 100
	}

	err = loadTemplateFromReader(f, &template)
	return template, err
}

func loadTemplateFromReader(reader io.Reader, template *NetworkTemplate) error {
	dec := json.NewDecoder(reader)
	return dec.Decode(template)
}

// Validate a specific network template to ensure it's rational, consistent, and complete
func (t NetworkTemplate) Validate() error {
	// Genesis wallet percentages must add up to 100
	// Genesis account names must be unique
	totalPct := big.NewFloat(float64(0))
	accounts := make(map[string]bool)
	for _, wallet := range t.Genesis.Wallets {
		if wallet.Stake < 0 {
			return fmt.Errorf("invalid template: negative stake on Genesis account %s", wallet.Name)
		}
		totalPct = totalPct.Add(totalPct, big.NewFloat(wallet.Stake))
		upperAcct := strings.ToUpper(wallet.Name)
		if _, found := accounts[upperAcct]; found {
			return fmt.Errorf("invalid template: duplicate Genesis account %s", wallet.Name)
		}
		accounts[upperAcct] = true
	}

	totalPctInt, _ := totalPct.Int64()
	const epsilon = 0.0000001
	if totalPctInt != 100 {
		totalPctFloat, _ := totalPct.Float64()
		if totalPctInt < 100 && totalPctFloat > (100.0-epsilon) {
			// ignore. This is a rounding error.
		} else {
			return fmt.Errorf("invalid template: Genesis account allocations must total 100 (actual %v)", totalPct)
		}
	}

	// No wallet can be assigned to more than one node
	// At least one relay is required
	wallets := make(map[string]bool)
	relayCount := 0
	for _, cfg := range t.Nodes {
		if cfg.IsRelay {
			relayCount++
		}
		for _, wallet := range cfg.Wallets {
			upperWallet := strings.ToUpper(wallet.Name)
			if _, found := wallets[upperWallet]; found {
				return fmt.Errorf("invalid template: Wallet '%s' assigned to multiple nodes", wallet.Name)
			}
			wallets[upperWallet] = true
		}
	}
	if relayCount == 0 {
		return fmt.Errorf("invalid template: at least one relay is required")
	}

	return nil
}

func createConfigFile(node remote.NodeConfigGoal, configFile string, numNodes int) error {
	cfg := config.GetDefaultLocal()
	cfg.GossipFanout = numNodes
	// Override default :8080 REST endpoint, and disable SRV lookup
	cfg.EndpointAddress = "127.0.0.1:0"
	cfg.DNSBootstrapID = ""
	cfg.EnableProfiler = true

	if node.IsRelay {
		// Have relays listen on any localhost port
		cfg.NetAddress = "127.0.0.1:0"
	} else {
		// Non-relays should not open incoming connections
		cfg.IncomingConnectionsLimit = 0
	}

	if node.DeadlockDetection != 0 {
		cfg.DeadlockDetection = node.DeadlockDetection
	}
	return cfg.SaveToFile(configFile)
}
