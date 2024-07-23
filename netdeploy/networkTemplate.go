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

package netdeploy

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/network/p2p"
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

func (t NetworkTemplate) generateGenesisAndWallets(targetFolder, networkName string) error {
	genesisData := t.Genesis
	genesisData.NetworkName = networkName
	mergedConsensus := config.Consensus.Merge(t.Consensus)
	return gen.GenerateGenesisFiles(genesisData, mergedConsensus, targetFolder, os.Stdout)
}

// Create data folders for all NodeConfigs, configuring relays appropriately and
// returning the full path to the 'prime' relay and node folders (the first one created) and the genesis data used in this network.
func (t NetworkTemplate) createNodeDirectories(targetFolder string, binDir string, importKeys bool) (relayDirs []string, nodeDirs map[string]string, err error) {
	genesisFile := filepath.Join(targetFolder, genesisFileName)

	nodeDirs = make(map[string]string)
	importKeysCmd := filepath.Join(binDir, "goal")

	genesis, err := bookkeeping.LoadGenesisFromFile(filepath.Join(targetFolder, "genesis.json"))
	if err != nil {
		return
	}
	genesisVer := genesis.ID()

	relaysCount := countRelayNodes(t.Nodes)

	for i, cfg := range t.Nodes {
		nodeDir := filepath.Join(targetFolder, cfg.Name)
		err = os.Mkdir(nodeDir, os.ModePerm)
		if err != nil {
			if !os.IsExist(err) {
				return
			}

			// allow some flexibility around pre-existing directories to
			// support docker and pre-mounted volumes.
			if !util.IsEmpty(nodeDir) {
				err = fmt.Errorf("duplicate node directory detected: %w", err)
				return
			}
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

		var files []fs.DirEntry
		files, err = os.ReadDir(targetFolder)
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
			if err != nil {
				return
			}
			_, err = client.CreateWallet(libgoal.UnencryptedWalletName, nil, crypto.MasterDerivationKey{})
			if err != nil {
				return
			}

			stdout, stderr, execErr := util.ExecAndCaptureOutput(importKeysCmd, "account", "importrootkey", "-w", string(libgoal.UnencryptedWalletName), "-d", nodeDir)
			if execErr != nil {
				return nil, nil, fmt.Errorf("goal account importrootkey failed: %w\nstdout: %s\nstderr: %s", execErr, stdout, stderr)
			}
		}

		// Create any necessary config.json file for this node
		nodeCfg := filepath.Join(nodeDir, config.ConfigFilename)
		var mergedCfg config.Local
		mergedCfg, err = createConfigFile(cfg, nodeCfg, len(t.Nodes)-1, relaysCount) // minus 1 to avoid counting self
		if err != nil {
			return
		}

		if mergedCfg.EnableP2P {
			// generate peer ID file for this node
			sk, pkErr := p2p.GetPrivKey(config.Local{P2PPersistPeerID: true}, genesisDir)
			if pkErr != nil {
				return nil, nil, pkErr
			}
			pid, pErr := p2p.PeerIDFromPublicKey(sk.GetPublic())
			if pErr != nil {
				return nil, nil, pErr
			}
			t.Nodes[i].P2PPeerID = string(pid)
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

	err = LoadTemplateFromReader(f, &template)
	return template, err
}

// LoadTemplateFromReader loads and decodes a network template
func LoadTemplateFromReader(reader io.Reader, template *NetworkTemplate) error {

	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		// for arm machines, use smaller key dilution
		template.Genesis.PartKeyDilution = 100
	}
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
	wallets := make(map[string]bool)
	for _, cfg := range t.Nodes {
		for _, wallet := range cfg.Wallets {
			upperWallet := strings.ToUpper(wallet.Name)
			if _, found := wallets[upperWallet]; found {
				return fmt.Errorf("invalid template: Wallet '%s' assigned to multiple nodes", wallet.Name)
			}
			wallets[upperWallet] = true
		}
	}

	// At least one relay is required
	if len(t.Nodes) > 1 && countRelayNodes(t.Nodes) == 0 {
		return fmt.Errorf("invalid template: at least one relay is required when more than a single node presents")
	}

	// Validate JSONOverride decoding
	for _, cfg := range t.Nodes {
		local := config.GetDefaultLocal()
		err := decodeJSONOverride(cfg.ConfigJSONOverride, &local)
		if err != nil {
			return fmt.Errorf("invalid template: unable to decode JSONOverride: %w", err)
		}
	}

	// Follow nodes cannot be relays
	// Relays cannot have peer list
	for _, cfg := range t.Nodes {
		if cfg.IsRelay && isEnableFollowMode(cfg.ConfigJSONOverride) {
			return fmt.Errorf("invalid template: follower nodes may not be relays")
		}
		if cfg.IsRelay && len(cfg.PeerList) > 0 {
			return fmt.Errorf("invalid template: relays may not have a peer list")
		}
	}

	if t.Genesis.DevMode && len(t.Nodes) != 1 {
		if countRelayNodes(t.Nodes) != 1 {
			return fmt.Errorf("invalid template: devmode configurations may have at most one relay")
		}

		for _, cfg := range t.Nodes {
			if !cfg.IsRelay && !isEnableFollowMode(cfg.ConfigJSONOverride) {
				return fmt.Errorf("invalid template: devmode configurations may only contain one relay and follower nodes")
			}
		}
	}

	return nil
}

func isEnableFollowMode(JSONOverride string) bool {
	local := config.GetDefaultLocal()
	// decode error is checked elsewhere
	_ = decodeJSONOverride(JSONOverride, &local)
	return local.EnableFollowMode
}

// countRelayNodes counts the total number of relays
func countRelayNodes(nodeCfgs []remote.NodeConfigGoal) (relayCount int) {
	for _, cfg := range nodeCfgs {
		if cfg.IsRelay {
			relayCount++
		}
	}
	return
}

func decodeJSONOverride(override string, cfg *config.Local) error {
	if override != "" {
		reader := strings.NewReader(override)
		dec := json.NewDecoder(reader)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return err
		}
	}
	return nil
}

func createConfigFile(node remote.NodeConfigGoal, configFile string, numNodes int, relaysCount int) (config.Local, error) {
	cfg := config.GetDefaultLocal()
	cfg.GossipFanout = numNodes
	// Override default :8080 REST endpoint, and disable SRV lookup
	cfg.EndpointAddress = "127.0.0.1:0"
	cfg.DNSBootstrapID = ""
	cfg.EnableProfiler = true
	cfg.EnableRuntimeMetrics = true
	cfg.EnableExperimentalAPI = true
	if relaysCount == 0 {
		cfg.DisableNetworking = true
	}

	if node.IsRelay {
		// Have relays listen on any localhost port
		cfg.NetAddress = "127.0.0.1:0"

		cfg.Archival = false                // make it explicit non-archival
		cfg.MaxBlockHistoryLookback = 20000 // to save blocks beyond MaxTxnLife=13
	} else {
		// Non-relays should not open incoming connections
		cfg.IncomingConnectionsLimit = 0
	}

	if node.DeadlockDetection != 0 {
		cfg.DeadlockDetection = node.DeadlockDetection
	}

	err := decodeJSONOverride(node.ConfigJSONOverride, &cfg)
	if err != nil {
		return config.Local{}, err
	}

	return cfg, cfg.SaveToFile(configFile)
}
