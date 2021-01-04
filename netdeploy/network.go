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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/util"
)

const configFileName = "network.json"
const genesisFileName = config.GenesisJSONFile
const maxGetRelayAddressRetry = 50

// NetworkCfg contains the persisted configuration of the deployed network
type NetworkCfg struct {
	Name string
	// RelayDirs are directories where relays live (where we check for connection IP:Port)
	// They are stored relative to root dir (e.g. "Primary")
	RelayDirs    []string
	TemplateFile string // Template file used to create the network
}

// Network represents an instance of a deployed network
type Network struct {
	rootDir          string
	cfg              NetworkCfg
	nodeDirs         map[string]string // mapping between the node name and the directories where the node is operation on (not including RelayDirs)
	gen              gen.GenesisData
	nodeExitCallback nodecontrol.AlgodExitErrorCallback
}

// CreateNetworkFromTemplate uses the specified template to deploy a new private network
// under the specified root directory.
func CreateNetworkFromTemplate(name, rootDir, templateFile, binDir string, importKeys bool, nodeExitCallback nodecontrol.AlgodExitErrorCallback, consensus config.ConsensusProtocols) (Network, error) {
	n := Network{
		rootDir:          rootDir,
		nodeExitCallback: nodeExitCallback,
	}
	n.cfg.Name = name
	n.cfg.TemplateFile = templateFile

	template, err := loadTemplate(templateFile)
	if err == nil {
		err = template.Validate()
	}
	if err != nil {
		return n, err
	}

	// Create the network root directory so we can generate genesis.json and prepare node data directories
	err = os.MkdirAll(rootDir, os.ModePerm)
	if err != nil {
		return n, err
	}
	template.Consensus = consensus
	err = template.generateGenesisAndWallets(rootDir, name, binDir)
	if err != nil {
		return n, err
	}

	n.cfg.RelayDirs, n.nodeDirs, n.gen, err = template.createNodeDirectories(rootDir, binDir, importKeys)
	if err != nil {
		return n, err
	}

	err = n.Save(rootDir)
	n.SetConsensus(binDir, consensus)
	return n, err
}

// LoadNetwork loads and initializes the Network state representing
// an existing deployed network.
func LoadNetwork(rootDir string) (Network, error) {
	n := Network{
		rootDir: rootDir,
	}

	if !isValidNetworkDir(rootDir) {
		return n, fmt.Errorf("does not appear to be a valid network root directory: %s", rootDir)
	}

	cfgFile := filepath.Join(rootDir, configFileName)

	var err error
	n.cfg, err = loadNetworkCfg(cfgFile)
	if err != nil {
		return n, err
	}

	err = n.scanForNodes()
	return n, err
}

func loadNetworkCfg(configFile string) (NetworkCfg, error) {
	cfg := NetworkCfg{}
	f, err := os.Open(configFile)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	err = dec.Decode(&cfg)
	return cfg, err
}

// Name returns the name of the private network
func (n Network) Name() string {
	return n.cfg.Name
}

// PrimaryDataDir returns the primary data directory for the network
func (n Network) PrimaryDataDir() string {
	return n.getNodeFullPath(n.cfg.RelayDirs[0])
}

// NodeDataDirs returns an array of node data directories (not the relays)
func (n Network) NodeDataDirs() []string {
	var directories []string
	for _, nodeDir := range n.nodeDirs {
		directories = append(directories, n.getNodeFullPath(nodeDir))
	}
	return directories
}

// GetNodeDir returns the node directory that is associated with the given node name.
func (n Network) GetNodeDir(nodeName string) (string, error) {
	possibleDir := n.getNodeFullPath(nodeName)
	if isNodeDir(possibleDir) {
		return possibleDir, nil
	}
	return "", fmt.Errorf("no node exists that is named '%s'", nodeName)
}

func isNodeDir(path string) bool {
	if util.IsDir(path) {
		if util.FileExists(filepath.Join(path, config.GenesisJSONFile)) {
			return true
		}
	}
	return false
}

// Genesis returns the genesis data for this network
func (n Network) Genesis() gen.GenesisData {
	return n.gen
}

func isValidNetworkDir(rootDir string) bool {
	cfgFile := filepath.Join(rootDir, configFileName)
	fileExists := util.FileExists(cfgFile)

	// If file exists, network assumed to exist
	if !fileExists {
		return false
	}

	// Now check for genesis.json file too
	cfgFile = filepath.Join(rootDir, genesisFileName)
	fileExists = util.FileExists(cfgFile)
	return fileExists
}

// Save persists the network state in the root directory (in network.json)
func (n Network) Save(rootDir string) error {
	cfgFile := filepath.Join(rootDir, configFileName)
	return saveNetworkCfg(n.cfg, cfgFile)
}

func (n Network) getNodeFullPath(nodeDir string) string {
	return filepath.Join(n.rootDir, nodeDir)
}

func saveNetworkCfg(cfg NetworkCfg, configFile string) error {
	f, err := os.Create(configFile)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	err = enc.Encode(&cfg)
	return err
}

func (n *Network) scanForNodes() error {
	// Enumerate direct sub-directories of our root and look for valid node data directories (where genesis.json exists)
	entries, err := ioutil.ReadDir(n.rootDir)
	if err != nil {
		return err
	}

	nodes := make(map[string]string)
	sawPrimeDir := false

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		nodeName := entry.Name()
		genesisFile := filepath.Join(n.getNodeFullPath(nodeName), genesisFileName)
		fileExists := util.FileExists(genesisFile)
		if fileExists {
			isPrimeDir := strings.EqualFold(nodeName, n.cfg.RelayDirs[0])
			if isPrimeDir {
				sawPrimeDir = true
			} else {
				nodes[nodeName] = nodeName
			}
		}
	}
	if !sawPrimeDir {
		return fmt.Errorf("primary relay directory (%s) invalid - can't run", n.cfg.RelayDirs[0])
	}
	n.nodeDirs = nodes
	return nil
}

// Start the network, ensuring primary relay starts first
func (n Network) Start(binDir string, redirectOutput bool) error {
	// Start relays
	// Determine IP:PORT for said relays
	// Start remaining nodes, pointing at the relays
	// Wait for all to start, collect errors if any

	// Start Prime Relay and get its listening address

	var peerAddressListBuilder strings.Builder
	var relayAddress string
	var err error
	for _, relayDir := range n.cfg.RelayDirs {
		nodeFulllPath := n.getNodeFullPath(relayDir)
		nc := nodecontrol.MakeNodeController(binDir, nodeFulllPath)
		args := nodecontrol.AlgodStartArgs{
			RedirectOutput:    redirectOutput,
			ExitErrorCallback: n.nodeExitCallback,
			PeerAddress:       relayAddress, // on the first iteration it would be empty, which is ok. subsequent iterations would link all the relays.
		}

		_, err := nc.StartAlgod(args)
		if err != nil {
			return err
		}

		relayAddress, err = n.getRelayAddress(nc)
		if err != nil {
			return err
		}

		if peerAddressListBuilder.Len() != 0 {
			peerAddressListBuilder.WriteString(";")
		}
		peerAddressListBuilder.WriteString(relayAddress)
	}

	peerAddressList := peerAddressListBuilder.String()
	err = n.startNodes(binDir, peerAddressList, redirectOutput)
	return err
}

// retry fetching the relay address
func (n Network) getRelayAddress(nc nodecontrol.NodeController) (relayAddress string, err error) {
	for i := 1; ; i++ {
		relayAddress, err = nc.GetListeningAddress()
		if err == nil {
			return
		}
		if i <= maxGetRelayAddressRetry {
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}
	return
}

// GetPeerAddresses returns an array of Relay addresses, if any; to be used to start nodes
// outside of the main 'Start' call.
func (n Network) GetPeerAddresses(binDir string) []string {
	var peerAddresses []string
	for _, relayDir := range n.cfg.RelayDirs {
		nc := nodecontrol.MakeNodeController(binDir, n.getNodeFullPath(relayDir))
		relayAddress, err := nc.GetListeningAddress()
		if err != nil {
			continue
		}
		if strings.HasPrefix(relayAddress, "http://") {
			relayAddress = relayAddress[7:]
		}
		peerAddresses = append(peerAddresses, relayAddress)
	}
	return peerAddresses
}

func (n Network) startNodes(binDir, relayAddress string, redirectOutput bool) error {
	args := nodecontrol.AlgodStartArgs{
		PeerAddress:       relayAddress,
		RedirectOutput:    redirectOutput,
		ExitErrorCallback: n.nodeExitCallback,
	}
	for _, nodeDir := range n.nodeDirs {
		nc := nodecontrol.MakeNodeController(binDir, n.getNodeFullPath(nodeDir))
		_, err := nc.StartAlgod(args)
		if err != nil {
			return err
		}
	}
	return nil
}

// StartNode can be called to start a node after the network has been started.
// It determines the correct PeerAddresses to use.
func (n Network) StartNode(binDir, nodeDir string, redirectOutput bool) (err error) {
	controller := nodecontrol.MakeNodeController(binDir, nodeDir)
	peers := n.GetPeerAddresses(binDir)
	peerAddresses := strings.Join(peers, ";")
	_, err = controller.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:    peerAddresses,
		RedirectOutput: redirectOutput,
	})
	return
}

// Stop the network, ensuring primary relay stops first
// No return code - we try to kill them if we can (if we read valid PID file)
func (n Network) Stop(binDir string) {
	c := make(chan struct{}, len(n.cfg.RelayDirs)+len(n.nodeDirs))
	stopNodeContoller := func(nc *nodecontrol.NodeController) {
		defer func() {
			c <- struct{}{}
		}()
		nc.FullStop()
	}
	for _, relayDir := range n.cfg.RelayDirs {
		relayDataDir := n.getNodeFullPath(relayDir)
		nc := nodecontrol.MakeNodeController(binDir, relayDataDir)
		algodKmdPath, _ := filepath.Abs(filepath.Join(relayDataDir, libgoal.DefaultKMDDataDir))
		nc.SetKMDDataDir(algodKmdPath)
		go stopNodeContoller(&nc)
	}
	for _, nodeDir := range n.nodeDirs {
		nodeDataDir := n.getNodeFullPath(nodeDir)
		nc := nodecontrol.MakeNodeController(binDir, nodeDataDir)
		algodKmdPath, _ := filepath.Abs(filepath.Join(nodeDataDir, libgoal.DefaultKMDDataDir))
		nc.SetKMDDataDir(algodKmdPath)
		go stopNodeContoller(&nc)
	}
	// wait until we finish stopping all the node controllers.
	for i := cap(c); i > 0; i-- {
		<-c
	}
	close(c)
}

// NetworkNodeStatus represents the result from checking the status of a particular node instance
type NetworkNodeStatus struct {
	Status generatedV2.NodeStatusResponse
	Error  error
}

// GetGoalClient returns the libgoal.Client for the specified node name
func (n Network) GetGoalClient(binDir, nodeName string) (lg libgoal.Client, err error) {
	nodeDir, err := n.GetNodeDir(nodeName)
	if err != nil {
		return
	}
	return libgoal.MakeClientWithBinDir(binDir, nodeDir, nodeDir, libgoal.DynamicClient)
}

// GetNodeController returns the node controller for the specified node name
func (n Network) GetNodeController(binDir, nodeName string) (nc nodecontrol.NodeController, err error) {
	nodeDir, err := n.GetNodeDir(nodeName)
	if err != nil {
		return
	}
	nc = nodecontrol.MakeNodeController(binDir, nodeDir)
	return
}

// NodesStatus retrieves the status of all nodes in the network and returns the status/error for each
func (n Network) NodesStatus(binDir string) map[string]NetworkNodeStatus {
	statuses := make(map[string]NetworkNodeStatus)

	for _, relayDir := range n.cfg.RelayDirs {
		var status generatedV2.NodeStatusResponse
		nc := nodecontrol.MakeNodeController(binDir, n.getNodeFullPath(relayDir))
		algodClient, err := nc.AlgodClient()
		if err == nil {
			status, err = algodClient.Status()
		}
		statuses[relayDir] = NetworkNodeStatus{
			status,
			err,
		}
	}

	for _, nodeDir := range n.nodeDirs {
		var status generatedV2.NodeStatusResponse
		nc := nodecontrol.MakeNodeController(binDir, n.getNodeFullPath(nodeDir))
		algodClient, err := nc.AlgodClient()
		if err == nil {
			status, err = algodClient.Status()
		}
		statuses[nodeDir] = NetworkNodeStatus{
			status,
			err,
		}
	}

	return statuses
}

// Delete the network - try stopping it first if we can.
// No return code - we try to kill them if we can (if we read valid PID file)
func (n Network) Delete(binDir string) error {
	n.Stop(binDir)
	return os.RemoveAll(n.rootDir)
}

// SetConsensus applies a new consensus settings which would get deployed before
// any of the nodes starts
func (n Network) SetConsensus(binDir string, consensus config.ConsensusProtocols) error {
	for _, relayDir := range n.cfg.RelayDirs {
		relayFulllPath := n.getNodeFullPath(relayDir)
		nc := nodecontrol.MakeNodeController(binDir, relayFulllPath)
		err := nc.SetConsensus(consensus)
		if err != nil {
			return err
		}
	}
	for _, nodeDir := range n.nodeDirs {
		nodeFulllPath := n.getNodeFullPath(nodeDir)
		nc := nodecontrol.MakeNodeController(binDir, nodeFulllPath)
		err := nc.SetConsensus(consensus)
		if err != nil {
			return err
		}
	}
	return nil
}
