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

package nodecfg

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/tools/network/cloudflare"
	"github.com/algorand/go-algorand/util"
)

type nodeConfigurator struct {
	config                  remote.HostConfig
	dnsName                 string
	genesisFile             string
	genesisData             bookkeeping.Genesis
	bootstrappedBlockFile   string
	bootstrappedTrackerFile string
	bootstrappedTrackerDir  string
	relayEndpoints          []srvEntry
	metricsEndpoints        []srvEntry
	p2pBootstrapEndpoints   []txtEntry
}

type srvEntry struct {
	srvName string
	port    string
}

type txtEntry struct {
	netAddress string
	peerID     string
}

// ApplyConfigurationToHost attempts to apply the provided configuration to the local host,
// based on the configuration specified for the provided hostName, with node
// directories being created / updated under the specified rootNodeDir
func ApplyConfigurationToHost(cfg remote.HostConfig, rootConfigDir, rootNodeDir string, dnsName string) (err error) {
	nc := nodeConfigurator{
		config:  cfg,
		dnsName: dnsName,
	}

	return nc.apply(rootConfigDir, rootNodeDir)
}

// Apply the configuration.  For now, assume initial installation - not an update.
//
// Copy node directories from configuration folder to the rootNodeDir
// Then configure
func (nc *nodeConfigurator) apply(rootConfigDir, rootNodeDir string) (err error) {

	blockFile := filepath.Join(rootConfigDir, "genesisdata", "bootstrapped.block.sqlite")
	blockFileExists := util.FileExists(blockFile)
	if blockFileExists {
		nc.bootstrappedBlockFile = blockFile
	}

	trackerFile := filepath.Join(rootConfigDir, "genesisdata", "bootstrapped.tracker.sqlite")
	trackerFileExists := util.FileExists(trackerFile)
	if trackerFileExists {
		nc.bootstrappedTrackerFile = trackerFile
	}

	trackerDir := filepath.Join(rootConfigDir, "genesisdata", "bootstrapped")
	trackerDirExists := util.FileExists(trackerDir)
	if trackerDirExists {
		nc.bootstrappedTrackerDir = trackerDir
	}

	nc.genesisFile = filepath.Join(rootConfigDir, "genesisdata", config.GenesisJSONFile)
	nc.genesisData, err = bookkeeping.LoadGenesisFromFile(nc.genesisFile)
	if err != nil {
		return fmt.Errorf("error loading genesis from '%s': %v", nc.genesisFile, err)

	}
	nodeDirs, err := nc.prepareNodeDirs(nc.config.Nodes, rootConfigDir, rootNodeDir)
	if err != nil {
		return fmt.Errorf("error preparing node directories: %v", err)
	}

	for _, nodeDir := range nodeDirs {
		nodeDir.delaySave = true
		err = nodeDir.configure()
		if err != nil {
			break
		}
		nodeDir.delaySave = false
		fmt.Fprint(os.Stdout, "... saving config\n")
		nodeDir.saveConfig()
	}

	if err == nil && nc.dnsName != "" {
		fmt.Fprint(os.Stdout, "... registering DNS / SRV records\n")
		err = nc.registerDNSRecords()
	}

	return
}

func (nc *nodeConfigurator) prepareNodeDirs(configs []remote.NodeConfig, rootConfigDir, rootNodeDir string) (nodeDirs []nodeDir, err error) {
	rootHostDir := filepath.Join(rootConfigDir, "hosts", nc.config.Name)
	genesisDir := nc.genesisData.ID()

	// Importing root keys is complicated - just use goal's support for it
	goalPath, err := filepath.Abs(filepath.Join(rootNodeDir, ".."))
	if err != nil {
		return
	}
	importKeysCmd := filepath.Join(goalPath, "goal")

	for _, node := range configs {
		nodeSrc := filepath.Join(rootHostDir, node.Name)
		nodeDest := filepath.Join(rootNodeDir, node.Name)

		fmt.Fprintf(os.Stdout, "Creating node %s in %s...\n", node.Name, nodeDest)
		err = util.CopyFolder(nodeSrc, nodeDest)
		if err != nil {
			return
		}

		// Copy the genesis.json file
		_, err = util.CopyFile(nc.genesisFile, filepath.Join(nodeDest, config.GenesisJSONFile))
		if err != nil {
			return
		}

		// Copy wallet files into current ledger folder and import the wallets
		//
		fmt.Fprintf(os.Stdout, "... copying wallets to ledger folder ...\n")
		err = util.CopyFolderWithFilter(nodeDest, filepath.Join(nodeDest, genesisDir), filterWalletFiles)
		if err != nil {
			return
		}

		fmt.Fprintf(os.Stdout, "... importing wallets into kmd ...\n")
		err = importWalletFiles(importKeysCmd, nodeDest)
		if err != nil {
			return
		}

		// Copy the bootstrapped files into current ledger folder
		if nc.bootstrappedBlockFile != "" &&
			(nc.bootstrappedTrackerFile != "" || nc.bootstrappedTrackerDir != "") {
			fmt.Fprintf(os.Stdout, "... copying block database file to ledger folder ...\n")
			dest := filepath.Join(nodeDest, genesisDir, fmt.Sprintf("%s.block.sqlite", config.LedgerFilenamePrefix))
			_, err = util.CopyFile(nc.bootstrappedBlockFile, dest)
			if err != nil {
				return nil, fmt.Errorf("failed to copy database file %s from %s to %s : %w", "bootstrapped.block.sqlite", filepath.Dir(nc.bootstrappedBlockFile), dest, err)
			}
			if nc.bootstrappedTrackerFile != "" {
				fmt.Fprintf(os.Stdout, "... copying tracker database file to ledger folder ...\n")
				dest = filepath.Join(nodeDest, genesisDir, fmt.Sprintf("%s.tracker.sqlite", config.LedgerFilenamePrefix))
				_, err = util.CopyFile(nc.bootstrappedTrackerFile, dest)
				if err != nil {
					return nil, fmt.Errorf("failed to copy database file %s from %s to %s : %w", filepath.Base(nc.bootstrappedBlockFile), filepath.Dir(nc.bootstrappedBlockFile), dest, err)
				}
			}
			if nc.bootstrappedTrackerDir != "" {
				fmt.Fprintf(os.Stdout, "... copying tracker database directory to ledger folder ...\n")
				dest = filepath.Join(nodeDest, genesisDir, config.LedgerFilenamePrefix)
				err = util.CopyFolder(nc.bootstrappedTrackerDir, dest)
				if err != nil {
					return nil, fmt.Errorf("failed to copy database directory from %s to %s : %w", nc.bootstrappedTrackerDir, dest, err)
				}
			}
		}

		nodeDirs = append(nodeDirs, nodeDir{
			NodeConfig:   node,
			dataDir:      nodeDest,
			configurator: nc,
		})
	}
	return
}

// getNetworkHostName creates a DNS name for a host
func (nc *nodeConfigurator) getNetworkHostName() string {
	return nc.config.Name + "." + string(nc.genesisData.Network) + ".algodev.network"
}

func (nc *nodeConfigurator) registerDNSRecords() (err error) {
	cfZoneID, cfToken, err := getClouldflareCredentials()
	if err != nil {
		return fmt.Errorf("error getting DNS credentials: %v", err)
	}

	cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfToken)

	const priority = 1
	const weight = 1
	const relayBootstrap = "_algobootstrap"
	const metricsSrv = "_metrics"
	const tcpProto = "_tcp"
	const proxied = false

	// If we need to register anything, first register a DNS entry
	// to map our network DNS name to our public name (or IP) provided to nodecfg
	// Network HostName = eg r1.testnet.algodev.network
	networkHostName := nc.getNetworkHostName()
	isIP := net.ParseIP(nc.dnsName) != nil
	var recordType string
	if isIP {
		recordType = "A"
	} else {
		recordType = "CNAME"
	}

	fmt.Fprintf(os.Stdout, "...... Adding DNS Record '%s' -> '%s' .\n", networkHostName, nc.dnsName)
	cloudflareDNS.SetDNSRecord(context.Background(), recordType, networkHostName, nc.dnsName, cloudflare.AutomaticTTL, priority, proxied)

	for _, entry := range nc.relayEndpoints {
		port, parseErr := strconv.ParseInt(strings.Split(entry.port, ":")[1], 10, 64)
		if parseErr != nil {
			return parseErr
		}
		fmt.Fprintf(os.Stdout, "...... Adding Relay SRV Record [%s.%s] '%s' [%d %d] -> '%s' .\n",
			relayBootstrap, tcpProto, entry.srvName, priority, port, networkHostName)
		err = cloudflareDNS.SetSRVRecord(context.Background(), entry.srvName, networkHostName,
			cloudflare.AutomaticTTL, priority, uint(port), relayBootstrap, tcpProto, weight)
		if err != nil {
			return
		}
	}

	for _, entry := range nc.metricsEndpoints {
		port, parseErr := strconv.ParseInt(strings.Split(entry.port, ":")[1], 10, 64)
		if parseErr != nil {
			fmt.Fprintf(os.Stdout, "Error parsing port for srv record: %s (port %v)\n", parseErr, entry)
			return parseErr
		}
		fmt.Fprintf(os.Stdout, "...... Adding Metrics SRV Record [%s.%s] '%s' [%d %d] -> '%s' .\n",
			metricsSrv, tcpProto, entry.srvName, priority, port, networkHostName)
		err = cloudflareDNS.SetSRVRecord(context.Background(), entry.srvName, networkHostName,
			cloudflare.AutomaticTTL, priority, uint(port), metricsSrv, tcpProto, weight)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Error creating srv record: %s (%v)\n", err, entry)
			return
		}
	}

	dnsaddrsFrom := fmt.Sprintf("_dnsaddr.%s.algodev.network", nc.genesisData.Network)
	for _, entry := range nc.p2pBootstrapEndpoints {
		port, parseErr := strconv.ParseInt(strings.Split(entry.netAddress, ":")[1], 10, 64)
		if parseErr != nil {
			return parseErr
		}
		var addrType string
		if isIP {
			addrType = "ip4"
		} else {
			addrType = "dnsaddr"
		}
		addrInfoString := fmt.Sprintf("/%s/%s/tcp/%d/p2p/%s", addrType, nc.dnsName, port, entry.peerID)
		to := fmt.Sprintf("dnsaddr=%s", addrInfoString)

		fmt.Fprintf(os.Stdout, "...... Adding P2P TXT Record '%s' -> '%s' .\n", dnsaddrsFrom, to)
		const priority = 1
		const proxied = false
		dnsErr := cloudflareDNS.CreateDNSRecord(context.Background(), "TXT", dnsaddrsFrom, to, cloudflare.AutomaticTTL, priority, proxied)
		if dnsErr != nil {
			return dnsErr
		}
	}

	return
}

func getClouldflareCredentials() (zoneID string, token string, err error) {
	zoneID = os.Getenv("CLOUDFLARE_ZONE_ID")
	token = os.Getenv("CLOUDFLARE_API_TOKEN")
	if zoneID == "" || token == "" {
		err = fmt.Errorf("one or more credentials missing from ENV")
	}
	return
}

func importWalletFiles(importKeysCmd string, nodeDir string) error {
	_, _, err := util.ExecAndCaptureOutput(importKeysCmd, "account", "importrootkey", "-d", nodeDir, "-u")
	return err
}

func filterWalletFiles(name string, info os.FileInfo) bool {
	if info.IsDir() {
		return false
	}

	ext := filepath.Ext(info.Name())
	return ext == ".partkey" || ext == ".rootkey"
}

func (nc *nodeConfigurator) addRelaySrv(srvRecord string, port string) {
	nc.relayEndpoints = append(nc.relayEndpoints, srvEntry{srvRecord, port})
}

func (nc *nodeConfigurator) registerMetricsSrv(srvRecord string, port string) {
	nc.metricsEndpoints = append(nc.metricsEndpoints, srvEntry{srvRecord, port})
}

func (nc *nodeConfigurator) addP2PBootstrap(netAddress string, peerID string) {
	nc.p2pBootstrapEndpoints = append(nc.p2pBootstrapEndpoints, txtEntry{netAddress, peerID})
}
