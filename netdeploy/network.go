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

package netdeploy

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
)

const configFileName = "network.json"
const genesisFileName = config.GenesisJSONFile
const maxGetRelayAddressRetry = 50

// NetworkCfg contains the persisted configuration of the deployed network
type NetworkCfg struct {
	Name string `json:"Name,omitempty"`
	// RelayDirs are directories where relays live (where we check for connection IP:Port)
	// They are stored relative to root dir (e.g. "Primary")
	RelayDirs []string        `json:"RelayDirs,omitempty"`
	Template  NetworkTemplate `json:"Template,omitempty"` // Template file used to create the network
}

// Network represents an instance of a deployed network
type Network struct {
	rootDir          string
	cfg              NetworkCfg
	nodeDirs         map[string]string // mapping between the node name and the directories where the node is operation on (not including RelayDirs)
	gen              gen.GenesisData
	nodeExitCallback nodecontrol.AlgodExitErrorCallback
}

// TemplateOverride is a function that modifies the NetworkTemplate after it is read in.
type TemplateOverride func(*NetworkTemplate)

// OverrideDevMode turns on dev mode, regardless of whether the json says so.
func OverrideDevMode(template *NetworkTemplate) {
	template.Genesis.DevMode = true
	if len(template.Nodes) > 0 {
		template.Nodes[0].IsRelay = false
	}
}

// OverrideConsensusVersion changes the protocol version of a template.
func OverrideConsensusVersion(ver protocol.ConsensusVersion) TemplateOverride {
	return func(template *NetworkTemplate) {
		template.Genesis.ConsensusProtocol = ver
	}
}

// OverrideKmdConfig changes the KMD config.
func OverrideKmdConfig(kmdConfig TemplateKMDConfig) TemplateOverride {
	return func(template *NetworkTemplate) {
		template.kmdConfig = kmdConfig
	}
}

// CreateNetworkFromTemplate uses the specified template to deploy a new private network
// under the specified root directory.
func CreateNetworkFromTemplate(name, rootDir string, templateReader io.Reader, binDir string, importKeys bool, nodeExitCallback nodecontrol.AlgodExitErrorCallback, consensus config.ConsensusProtocols, overrides ...TemplateOverride) (Network, error) {
	n := Network{
		rootDir:          rootDir,
		nodeExitCallback: nodeExitCallback,
	}
	n.cfg.Name = name

	var err error
	template := defaultNetworkTemplate

	if err = LoadTemplateFromReader(templateReader, &template); err != nil {
		return n, err
	}

	for _, overide := range overrides {
		overide(&template)
	}

	if err = template.Validate(); err != nil {
		return n, err
	}

	if n.cfg.Name == "" {
		n.cfg.Name = template.Genesis.NetworkName
	}
	if n.cfg.Name == "" {
		return n, fmt.Errorf("unnamed network. Use the \"network\" flag or \"Genesis.NetworkName\" in the network template")
	}

	// Create the network root directory so we can generate genesis.json and prepare node data directories
	err = os.MkdirAll(rootDir, os.ModePerm)
	if err != nil {
		return n, err
	}
	template.Consensus = consensus
	err = template.generateGenesisAndWallets(rootDir, n.cfg.Name)
	if err != nil {
		return n, err
	}

	n.cfg.RelayDirs, n.nodeDirs, err = template.createNodeDirectories(rootDir, binDir, importKeys)
	if err != nil {
		return n, err
	}
	n.gen = template.Genesis
	n.cfg.Template = template

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
	if !n.gen.DevMode || len(n.cfg.RelayDirs) > 0 {
		return n.getNodeFullPath(n.cfg.RelayDirs[0])
	}
	// for devmode, there should be only a single node, so pick it up.
	for nodeName := range n.nodeDirs {
		return n.getNodeFullPath(nodeName)
	}
	panic(fmt.Errorf("neither relay directories nor node directories are defined for the network"))
}

// RelayDataDirs returns an array of relay data directories (not the nodes)
func (n Network) RelayDataDirs() []string {
	var directories []string
	for _, dir := range n.cfg.RelayDirs {
		directories = append(directories, n.getNodeFullPath(dir))
	}
	sort.Strings(directories)
	return directories
}

// NodeDataDirs returns an array of node data directories (not the relays)
func (n Network) NodeDataDirs() []string {
	var directories []string
	for _, nodeDir := range n.nodeDirs {
		directories = append(directories, n.getNodeFullPath(nodeDir))
	}
	sort.Strings(directories)
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
	entries, err := os.ReadDir(n.rootDir)
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
			isPrimeDir := len(n.cfg.RelayDirs) > 0 && strings.EqualFold(nodeName, n.cfg.RelayDirs[0])
			if isPrimeDir {
				sawPrimeDir = true
			} else {
				nodes[nodeName] = nodeName
			}
		}
	}
	if !sawPrimeDir && len(nodes) > 1 {
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

	var relayAddress string
	var err error
	relayNameToAddress := map[string]string{}
	for _, relayDir := range n.cfg.RelayDirs {
		nodeFullPath := n.getNodeFullPath(relayDir)
		nc := nodecontrol.MakeNodeController(binDir, nodeFullPath)
		args := nodecontrol.AlgodStartArgs{
			RedirectOutput:    redirectOutput,
			ExitErrorCallback: n.nodeExitCallback,
			PeerAddress:       relayAddress, // on the first iteration it would be empty, which is ok. subsequent iterations would link all the relays.
		}

		_, err1 := nc.StartAlgod(args)
		if err1 != nil {
			return err1
		}

		relayAddress, err1 = n.getRelayAddress(nc)
		if err1 != nil {
			return err1
		}
		relayNameToAddress[relayDir] = relayAddress
	}

	err = n.startNodes(binDir, relayNameToAddress, redirectOutput)
	return err
}

// retry fetching the relay address
func (n Network) getRelayAddress(nc nodecontrol.NodeController) (string, error) {
	for i := 1; ; i++ {
		relayAddress, err := nc.GetListeningAddress()
		if err == nil {
			return relayAddress, nil
		}
		if i <= maxGetRelayAddressRetry {
			time.Sleep(100 * time.Millisecond)
		} else {
			return "", err
		}
	}
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
		peerAddresses = append(peerAddresses, strings.TrimPrefix(relayAddress, "http://"))
	}
	return peerAddresses
}

func (n Network) startNodes(binDir string, relayNameToAddress map[string]string, redirectOutput bool) error {
	allRelaysAddresses := strings.Join(slices.Collect(maps.Values(relayNameToAddress)), ";")

	nodeConfigToEntry := make(map[string]remote.NodeConfigGoal, len(n.cfg.Template.Nodes))
	for _, n := range n.cfg.Template.Nodes {
		nodeConfigToEntry[n.Name] = n
	}

	for _, nodeDir := range n.nodeDirs {
		args := nodecontrol.AlgodStartArgs{
			PeerAddress:       allRelaysAddresses,
			RedirectOutput:    redirectOutput,
			ExitErrorCallback: n.nodeExitCallback,
		}
		if n, ok := nodeConfigToEntry[nodeDir]; ok && len(n.PeerList) > 0 {
			relayNames := strings.Split(n.PeerList, ";")
			var peerAddresses []string
			for _, relayName := range relayNames {
				relayAddress, ok := relayNameToAddress[relayName]
				if !ok {
					return fmt.Errorf("relay %s is not defined in the network", relayName)
				}
				peerAddresses = append(peerAddresses, relayAddress)
			}
			args.PeerAddress = strings.Join(peerAddresses, ";")
		}

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
func (n Network) Stop(binDir string) (err error) {
	c := make(chan error, len(n.cfg.RelayDirs)+len(n.nodeDirs))
	stopNodeContoller := func(nc *nodecontrol.NodeController) {
		var stopErr error
		defer func() {
			c <- stopErr
		}()
		stopErr = nc.FullStop()
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
		stopErr := <-c
		if stopErr != nil {
			err = stopErr
		}
	}
	close(c)
	return err
}

// NetworkNodeStatus represents the result from checking the status of a particular node instance
type NetworkNodeStatus struct {
	Status model.NodeStatusResponse
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
		var status model.NodeStatusResponse
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
		var status model.NodeStatusResponse
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
		relayFullPath := n.getNodeFullPath(relayDir)
		nc := nodecontrol.MakeNodeController(binDir, relayFullPath)
		err := nc.SetConsensus(consensus)
		if err != nil {
			return err
		}
	}
	for _, nodeDir := range n.nodeDirs {
		nodeFullPath := n.getNodeFullPath(nodeDir)
		nc := nodecontrol.MakeNodeController(binDir, nodeFullPath)
		err := nc.SetConsensus(consensus)
		if err != nil {
			return err
		}
	}
	return nil
}
