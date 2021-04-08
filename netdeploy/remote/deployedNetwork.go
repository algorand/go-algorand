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

package remote

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/codecs"
)

const genesisFolderName = "genesisdata"
const hostFolderName = "hosts"
const networkConfigFileName = "network.config"
const topologySpecFileName = "cloudspec.config"

// ErrDeployedNetworkRootDirExists is returned by Validate if we're given a target folder that already exists
var ErrDeployedNetworkRootDirExists = fmt.Errorf("unable to generate deployed network files into existing directory")

// ErrDeployedNetworkInsufficientHosts is returned by Validate if our target network requires more hosts than the topology provides
var ErrDeployedNetworkInsufficientHosts = fmt.Errorf("target network requires more hosts than the topology provides")

// ErrDeployedNetworkNameCantIncludeWildcard is returned by Validate if network name contains '*'
var ErrDeployedNetworkNameCantIncludeWildcard = fmt.Errorf("network name cannont include wild-cards")

var BootstrappedNetState NetState

// ErrDeployedNetworkTemplate A template file contained {{Field}} sections that were not handled by a corresponding Field value in configuration.
type ErrDeployedNetworkTemplate struct {
	UnhandledTemplate string
}

// Error satisfies error interface
func (ednt ErrDeployedNetworkTemplate) Error() string {
	return fmt.Sprintf("config file contains unrecognized token: %s", ednt.UnhandledTemplate)
}

// DeployedNetworkConfig represents the complete configuration specification for a deployed network
type DeployedNetworkConfig struct {
	Hosts []HostConfig
}

// DeployedNetwork represents the complete configuration specification for a deployed network
type DeployedNetwork struct {
	useExistingGenesis       bool
	createBoostrappedNetwork bool
	GenesisData              gen.GenesisData
	Topology                 topology
	Hosts                    []HostConfig
	BootstrappedNet          BootstrappedNetwork
}

type NetState struct {
	nAccounts     int
	nAssets       int
	nApplications int
	round         basics.Round
	accounts      map[basics.Address]basics.AccountData
	genesisID     string
	genesisHash   crypto.Digest
	poolAddr      basics.Address
	sinkAddr      basics.Address
}

// InitDeployedNetworkConfig loads the DeployedNetworkConfig from a file
func InitDeployedNetworkConfig(file string, buildConfig BuildConfig) (cfg DeployedNetworkConfig, err error) {
	processedFile, err := loadAndProcessConfig(file, buildConfig)
	if err != nil {
		return
	}

	err = json.Unmarshal([]byte(processedFile), &cfg)
	return
}

func loadAndProcessConfig(file string, buildConfig BuildConfig) (expanded string, err error) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	expanded, err = replaceTokens(string(raw), buildConfig)
	return
}

func replaceTokens(original string, buildConfig BuildConfig) (expanded string, err error) {
	// Walk through tokens and replace them
	tokenPairs := make([]string, 0)
	tokenPairs = append(tokenPairs, "{{NetworkName}}", buildConfig.NetworkName)
	tokenPairs = append(tokenPairs, "{{NetworkPort}}", buildConfig.NetworkPort)
	tokenPairs = append(tokenPairs, "{{NetworkPort2}}", buildConfig.NetworkPort2)
	tokenPairs = append(tokenPairs, "{{NetworkPort3}}", buildConfig.NetworkPort3)
	tokenPairs = append(tokenPairs, "{{NetworkPort4}}", buildConfig.NetworkPort4)
	tokenPairs = append(tokenPairs, "{{APIEndpoint}}", buildConfig.APIEndpoint)
	tokenPairs = append(tokenPairs, "{{APIEndpoint2}}", buildConfig.APIEndpoint2)
	tokenPairs = append(tokenPairs, "{{APIEndpoint3}}", buildConfig.APIEndpoint3)
	tokenPairs = append(tokenPairs, "{{APIEndpoint4}}", buildConfig.APIEndpoint4)
	tokenPairs = append(tokenPairs, "{{APIToken}}", buildConfig.APIToken)
	tokenPairs = append(tokenPairs, "{{EnableTelemetry}}", strconv.FormatBool(buildConfig.EnableTelemetry))
	tokenPairs = append(tokenPairs, "{{TelemetryURI}}", buildConfig.TelemetryURI)
	tokenPairs = append(tokenPairs, "{{MetricsURI}}", buildConfig.MetricsURI)
	tokenPairs = append(tokenPairs, "{{RunAsService}}", strconv.FormatBool(buildConfig.RunAsService))
	tokenPairs = append(tokenPairs, "{{CrontabSchedule}}", buildConfig.CrontabSchedule)
	tokenPairs = append(tokenPairs, "{{EnableAlgoh}}", strconv.FormatBool(buildConfig.EnableAlgoh))
	tokenPairs = append(tokenPairs, "{{DashboardEndpoint}}", buildConfig.DashboardEndpoint)
	tokenPairs = append(tokenPairs, buildConfig.MiscStringString...)

	expanded = strings.NewReplacer(tokenPairs...).Replace(original)

	// To validate that there wasn't a typo in an intended token, look for obvious clues like "{{" or "}}"
	openIndex := strings.Index(expanded, "{{")
	closeIndex := strings.Index(expanded, "}}")
	if openIndex >= 0 || closeIndex >= 0 {
		if openIndex < 0 {
			openIndex = 0
		}
		if closeIndex < 0 {
			closeIndex = len(expanded) - 2
		}
		return "", ErrDeployedNetworkTemplate{expanded[openIndex : closeIndex+2]}
	}

	return
}

// LoadDeployedNetworkConfigFromDir loads a DeployedNetworkConfig from a directory
func LoadDeployedNetworkConfigFromDir(rootDir string) (cfg DeployedNetworkConfig, err error) {
	configFilename := filepath.Join(rootDir, networkConfigFileName)
	fmt.Printf("Loading network.config from %s\n", configFilename)
	f, err := os.Open(configFilename)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	err = dec.Decode(&cfg)
	return cfg, err
}

// SaveToDisk allows writing the expanded template to disk - before we convert to DeployedNetworkConfig)
func (cfg DeployedNetworkConfig) SaveToDisk(rootDir string) (err error) {
	configFile := filepath.Join(rootDir, networkConfigFileName)
	f, err := os.Create(configFile)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := codecs.NewFormattedJSONEncoder(f)
	err = enc.Encode(&cfg)
	return
}

// ResolveDeployedNetworkConfig resolves the DeployedNetworkConfig and returns a DeployedNetwork
// with GenesisData and Topology structures instantiated.
func (cfg DeployedNetworkConfig) ResolveDeployedNetworkConfig(genesisDataFile string, topologyFile string) (resolved DeployedNetwork, err error) {
	genesisData, err := gen.LoadGenesisData(genesisDataFile)
	if err != nil {
		return
	}

	topology, err := loadTopology(topologyFile)
	if err != nil {
		return
	}

	resolved = DeployedNetwork{
		GenesisData: genesisData,
		Topology:    topology,
		Hosts:       cfg.Hosts,
	}
	return
}

// TryGetHostConfig tries to find and return the HostConfig for the specified hostName
func (cfg DeployedNetworkConfig) TryGetHostConfig(hostName string) (config HostConfig, found bool) {
	for _, config = range cfg.Hosts {
		if config.Name == hostName {
			found = true
			return
		}
	}
	return
}

// SetUseExistingGenesisFiles sets the override flag indicating we should use existing genesis
// files instead of generating new ones.  This is useful for permanent networks like devnet and testnet.
// Returns the previous value.
func (cfg *DeployedNetwork) SetUseExistingGenesisFiles(useExisting bool) bool {
	old := cfg.useExistingGenesis
	cfg.useExistingGenesis = useExisting
	return old
}

// SetUseBoostrappedFiles sets the override flag indicating we should use existing genesis
// files instead of generating new ones.  This is useful for permanent networks like devnet and testnet.
// Returns the previous value.
func (cfg *DeployedNetwork) SetUseBoostrappedFiles(boostrappedFile bool) bool {
	old := cfg.createBoostrappedNetwork
	cfg.createBoostrappedNetwork = boostrappedFile
	return old
}

// Validate uses the specified template to deploy a new private network
// under the specified root directory.
func (cfg DeployedNetwork) Validate(buildCfg BuildConfig, rootDir string) (err error) {
	// Make sure target directory doesn't already exist
	exists := util.FileExists(rootDir)
	if exists && !cfg.useExistingGenesis {
		return ErrDeployedNetworkRootDirExists
	}

	// Network name cannot contain any whitespace (should check for any invalid path character as well)
	if err = validateFilename(buildCfg.NetworkName); err != nil {
		return
	}

	requiredHostCount := len(cfg.Hosts)
	providedHostCount := len(cfg.Topology.Hosts)
	if requiredHostCount > providedHostCount {
		return ErrDeployedNetworkInsufficientHosts
	}

	if err = verifyHostsAvailableByName(cfg.Hosts, cfg.Topology.Hosts); err != nil {
		return
	}

	return nil
}

// Validate that the string is a valid filename (we'll use it as part of a directory name somewhere)
func validateFilename(filename string) (err error) {
	if strings.Index(filename, "*") >= 0 {
		return ErrDeployedNetworkNameCantIncludeWildcard
	}
	file, err := ioutil.TempFile("", filename)
	if err == nil {
		file.Close()
		os.Remove(file.Name())
	}
	return
}

func verifyHostsAvailableByName(requiredHosts []HostConfig, providedHosts []cloudHostType) (err error) {
	// Create map of cloudHost names for easy lookup
	cloudHosts := make(map[string]bool)
	for _, host := range providedHosts {
		cloudHosts[host.Name] = true
	}

	for _, required := range requiredHosts {
		if !cloudHosts[required.Name] {
			return fmt.Errorf("provided topology missing host '%s'", required.Name)
		}
	}
	return nil
}

// BuildNetworkFromTemplate uses the specified template to deploy a new private network
// under the specified root directory.
func (cfg DeployedNetwork) BuildNetworkFromTemplate(buildCfg BuildConfig, rootDir string) (err error) {
	// Create the network root directory so we can generate genesis.json and prepare node data directories
	err = os.MkdirAll(rootDir, os.ModePerm)
	if err != nil {
		return
	}

	// Store genesis files in root/GenesisData
	genesisFolder := filepath.Join(rootDir, genesisFolderName)
	if cfg.useExistingGenesis {
		fmt.Println(" *** using existing genesis files ***")
	} else {
		if err = gen.GenerateGenesisFiles(cfg.GenesisData, config.Consensus, genesisFolder, true); err != nil {
			return
		}
	}

	rootHostFolder := filepath.Join(rootDir, hostFolderName)
	walletNameToDataMap, err := cfg.createHostFolders(rootHostFolder, genesisFolder)
	if err != nil {
		return
	}

	if err = cfg.copyWalletsToNodes(genesisFolder, walletNameToDataMap); err != nil {
		return
	}

	if cfg.createBoostrappedNetwork {
		fmt.Println("Generating db files")
		cfg.GenerateDatabaseFiles(cfg.BootstrappedNet, genesisFolder)
	}

	return
}

//GenerateDatabaseFiles generates database files according to the configurations
func (cfg DeployedNetwork) GenerateDatabaseFiles(fileCfgs BootstrappedNetwork, genesisFolder string) error {

	BootstrappedNetState.accounts = make(map[basics.Address]basics.AccountData)

	genesis, err := bookkeeping.LoadGenesisFromFile(genesisFolder + "/genesis.json")
	if err != nil {
		return err
	}

	BootstrappedNetState.genesisID = genesis.ID()
	BootstrappedNetState.genesisHash = crypto.Hash([]byte(genesis.ID()))
	srcWallet := getGenesisAlloc(fileCfgs.SourceWalletName, genesis.Allocation)
	if srcWallet.Address == "" {
		return fmt.Errorf("error finding source wallet address")

	}

	rewardsPool := getGenesisAlloc("RewardsPool", genesis.Allocation)
	if rewardsPool.Address == "" {
		return fmt.Errorf("error finding source rewards ppol address")

	}

	feeSink := getGenesisAlloc("FeeSink", genesis.Allocation)
	if feeSink.Address == "" {
		return fmt.Errorf("error finding fee sink address")

	}
	src, err := basics.UnmarshalChecksumAddress(srcWallet.Address)

	poolAddr, err := basics.UnmarshalChecksumAddress(rewardsPool.Address)
	if err != nil {
		return err
	}
	sinkAddr, err := basics.UnmarshalChecksumAddress(feeSink.Address)
	if err != nil {
		return err
	}

	//initial state
	BootstrappedNetState.nAccounts = fileCfgs.GeneratedAccountsCount
	BootstrappedNetState.nAssets = fileCfgs.GeneratedAssetsCount
	BootstrappedNetState.nApplications = fileCfgs.GeneratedApplicationCount

	BootstrappedNetState.accounts[poolAddr] = basics.MakeAccountData(basics.NotParticipating, rewardsPool.State.MicroAlgos)
	BootstrappedNetState.accounts[sinkAddr] = basics.MakeAccountData(basics.NotParticipating, feeSink.State.MicroAlgos)
	BootstrappedNetState.accounts[src] = basics.MakeAccountData(basics.Online, srcWallet.State.MicroAlgos)

	BootstrappedNetState.poolAddr = poolAddr
	BootstrappedNetState.sinkAddr = sinkAddr
	BootstrappedNetState.round = basics.Round(0)

	roundTrxCnt := fileCfgs.RoundTransactionsCount
	initState, err := generateInitState(src, roundTrxCnt)
	if err != nil {
		return err
	}
	localCfg := config.GetDefaultLocal()
	localCfg.Archival = true
	log := logging.NewLogger()
	l, err := ledger.OpenLedger(log, genesisFolder+"/bootstrapped", false, initState, localCfg)
	if err != nil {
		return err
	}
	prev, _ := l.Block(l.Latest())
	for i := 1; i < fileCfgs.NumRounds; i++ {
		BootstrappedNetState.round = basics.Round(i)
		blk, _ := createBlock(src, prev, roundTrxCnt)
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		err = l.AddBlock(blk, agreement.Certificate{Round: BootstrappedNetState.round})
		if err != nil {
			fmt.Printf("Error %s\n", err)
			return err
		}

		if i%20 == 0 {
			l.WaitForCommit(basics.Round(i))
		}

	}

	l.Close()
	return nil
}

func createSignedTx(src basics.Address, dst basics.Address) transactions.SignedTxn {
	var tx transactions.Transaction

	header := transactions.Header{
		Sender:      src,
		Fee:         basics.MicroAlgos{Raw: 1},
		FirstValid:  BootstrappedNetState.round,
		LastValid:   BootstrappedNetState.round,
		GenesisID:   BootstrappedNetState.genesisID,
		GenesisHash: BootstrappedNetState.genesisHash,
	}

	if BootstrappedNetState.nAssets > 0 {
		assetParam := basics.AssetParams{
			Total:    100,
			UnitName: "unit",
			Manager:  dst,
		}

		assetConfigFields := transactions.AssetConfigTxnFields{
			AssetParams: assetParam,
		}

		tx = transactions.Transaction{
			Type:                 protocol.AssetConfigTx,
			Header:               header,
			AssetConfigTxnFields: assetConfigFields,
		}

		BootstrappedNetState.nAssets--
	} else if BootstrappedNetState.nApplications > 0 {
		header.Sender = dst
		appCallFields := transactions.ApplicationCallTxnFields{
			OnCompletion: 0,
		}
		tx = transactions.Transaction{
			Type:                     protocol.ApplicationCallTx,
			Header:                   header,
			ApplicationCallTxnFields: appCallFields,
		}
		BootstrappedNetState.nApplications--
	} else {
		tx = transactions.Transaction{
			Type:   protocol.PaymentTx,
			Header: header,
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: dst,
				Amount:   basics.MicroAlgos{Raw: uint64(0)},
			},
		}
	}

	t := transactions.SignedTxn{Txn: tx}

	return t
}

func getGenesisAlloc(name string, allocation []bookkeeping.GenesisAllocation) bookkeeping.GenesisAllocation {
	for _, alloc := range allocation {
		if strings.ToLower(alloc.Comment) == strings.ToLower(name) {
			return alloc
		}
	}
	return bookkeeping.GenesisAllocation{}
}

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func generateInitState(src basics.Address, roundTrxCnt int) (ledger.InitState, error) {

	var initState ledger.InitState
	payset := make([]transactions.SignedTxnInBlock, 0, roundTrxCnt)
	txibs := make([]transactions.SignedTxnInBlock, 0, roundTrxCnt)

	initBlock := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			GenesisID:   BootstrappedNetState.genesisID,
			GenesisHash: BootstrappedNetState.genesisHash,
			Round:       BootstrappedNetState.round,
			RewardsState: bookkeeping.RewardsState{
				RewardsRate: 1,
				RewardsPool: BootstrappedNetState.poolAddr,
				FeeSink:     BootstrappedNetState.sinkAddr,
			},
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
		},
	}

	initBlock.RewardsLevel = 0

	for i := 0; i < roundTrxCnt; i++ {
		secretDst := keypair()
		dst := basics.Address(secretDst.SignatureVerifier)
		BootstrappedNetState.accounts[dst] = basics.MakeAccountData(basics.Online, basics.MicroAlgos{Raw: uint64(1000000)})

		stxn := createSignedTx(src, dst)
		txib, err := initBlock.EncodeSignedTxn(stxn, transactions.ApplyData{})
		if err != nil {
			return ledger.InitState{}, err
		}
		txibs = append(txibs, txib)
	}

	payset = append(payset, txibs...)

	initBlock.Payset = payset
	var err error
	initBlock.TxnRoot, err = initBlock.PaysetCommit()
	if err != nil {
		return ledger.InitState{}, err
	}

	initState.Block = initBlock
	initState.Accounts = BootstrappedNetState.accounts
	initState.GenesisHash = crypto.Hash([]byte(BootstrappedNetState.genesisID))
	return initState, nil
}

func createBlock(src basics.Address, prev bookkeeping.Block, roundTrxCnt int) (bookkeeping.Block, error) {
	payset := make([]transactions.SignedTxnInBlock, 0, roundTrxCnt)
	txibs := make([]transactions.SignedTxnInBlock, 0, roundTrxCnt)

	block := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			GenesisID:   BootstrappedNetState.genesisID,
			GenesisHash: BootstrappedNetState.genesisHash,
			Round:       BootstrappedNetState.round,
			RewardsState: bookkeeping.RewardsState{
				RewardsRate: 1,
				RewardsPool: BootstrappedNetState.poolAddr,
				FeeSink:     BootstrappedNetState.sinkAddr,
			},
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: prev.CurrentProtocol,
			},
		},
	}

	block.RewardsLevel = prev.RewardsLevel

	for i := 0; i < roundTrxCnt; i++ {
		secretDst := keypair()
		dst := basics.Address(secretDst.SignatureVerifier)
		BootstrappedNetState.accounts[dst] = basics.MakeAccountData(basics.Online, basics.MicroAlgos{Raw: uint64(1000000)})

		stxn := createSignedTx(src, dst)
		txib, err := block.EncodeSignedTxn(stxn, transactions.ApplyData{})
		if err != nil {
			return bookkeeping.Block{}, err
		}
		txibs = append(txibs, txib)
	}

	payset = append(payset, txibs...)

	block.Payset = payset
	var err error
	block.TxnRoot, err = block.PaysetCommit()
	if err != nil {
		return bookkeeping.Block{}, err
	}

	return block, nil
}

type walletTargetData struct {
	path     string
	partOnly bool
}

func (cfg DeployedNetwork) createHostFolders(targetFolder string, genesisFolder string) (walletNameToDataMap map[string]walletTargetData, err error) {
	walletNameToDataMap = make(map[string]walletTargetData)

	if err = os.Mkdir(targetFolder, os.ModePerm); err != nil {
		return
	}

	// Process Hosts, and Nodes within Hosts
	// Create directory structure of Host/Node*; keep track of which wallets go where (what node folders)
	for _, host := range cfg.Hosts {
		hostFolder := filepath.Join(targetFolder, host.Name)
		err = os.Mkdir(hostFolder, os.ModePerm)
		if err != nil {
			return
		}

		for _, node := range host.Nodes {
			nodeFolder := filepath.Join(hostFolder, node.Name)
			err = os.Mkdir(nodeFolder, os.ModePerm)
			if err != nil {
				return
			}

			for _, wallet := range node.Wallets {
				walletNameToDataMap[wallet.Name] = walletTargetData{
					path:     nodeFolder,
					partOnly: wallet.ParticipationOnly,
				}
			}
		}
	}
	return
}

func (cfg DeployedNetwork) copyWalletsToNodes(genesisFolder string, walletNameToDataMap map[string]walletTargetData) (err error) {
	var files []os.FileInfo
	files, err = ioutil.ReadDir(genesisFolder)
	if err != nil {
		return
	}

	for _, info := range files {
		name := info.Name()
		var filename string
		if config.IsRootKeyFilename(name) {
			filename = config.AccountNameFromRootKeyFilename(name)
		} else if config.IsPartKeyFilename(name) {
			filename = config.AccountNameFromPartKeyFilename(name)
		} else {
			continue
		}

		if walletData, has := walletNameToDataMap[filename]; has {
			// If it's a PartKey (not a root key), or we want both (not part only)...
			if !config.IsRootKeyFilename(name) || !walletData.partOnly {
				err = os.Rename(filepath.Join(genesisFolder, name), filepath.Join(walletData.path, name))
				if err != nil {
					return
				}
			}
		}
	}
	return
}

// ValidateTopology reconciles the requested topology and the provided host templates and ensures all
// referenced host types are valid.
func (cfg DeployedNetwork) ValidateTopology(templates HostTemplates) error {
	// Verify that every Host Template referenced is known
	for _, host := range cfg.Topology.Hosts {
		if _, has := templates.Hosts[host.Template]; !has {
			return fmt.Errorf("missing host template: %s", host.Template)
		}
	}
	return nil
}

type cloudHostConfiguration struct {
	RootStorage int
	SSD2        int
}

type cloudHostSpec struct {
	Name           string
	Group          string
	Provider       string
	Region         string
	InstanceType   string
	OutgoingPorts  string
	IncomingPorts  string
	ProtectedPorts string
	Configuration  cloudHostConfiguration
}

type topologySpec struct {
	Hosts []cloudHostSpec
}

func (spec topologySpec) saveToDisk(filename string) (err error) {
	prettyPrint := true
	return codecs.SaveObjectToFile(filename, spec, prettyPrint)
}

// GenerateCloudTemplate generates the Cloud Topology Template file that will be processed by the
// cloud provisioning toolchain.
func (cfg DeployedNetwork) GenerateCloudTemplate(templates HostTemplates, targetFolder string) (err error) {
	topology := topologySpec{}

	cloudHosts := make(map[string]cloudHostType)
	for _, host := range cfg.Topology.Hosts {
		cloudHosts[host.Name] = host
	}

	var hostSpec cloudHostSpec
	for _, host := range cfg.Hosts {
		cloudHost, has := cloudHosts[host.Name]
		if !has {
			return fmt.Errorf("error locating cloud host type '%s'", host.Name)
		}

		hostTemplate, has := templates.Hosts[cloudHost.Template]
		if !has {
			return fmt.Errorf("error locating cloud host template '%s'", cloudHost.Template)
		}

		hostSpec, err = createHostSpec(host, hostTemplate)
		if err != nil {
			return
		}

		hostSpec.Group = strings.TrimSpace(cloudHost.Group)

		topology.Hosts = append(topology.Hosts, hostSpec)
	}

	specName := filepath.Join(targetFolder, topologySpecFileName)
	err = topology.saveToDisk(specName)
	return
}

func createHostSpec(host HostConfig, template cloudHost) (hostSpec cloudHostSpec, err error) {
	// Gather host-wide details (# nodes, # relays, required ports)
	relayCount := 0
	nodeCount := len(host.Nodes)
	ports := make(map[int]bool)
	portList := make([]string, 0)

	defaultConfig := config.GetDefaultLocal()
	var port int
	for _, node := range host.Nodes {
		if node.IsRelay() {
			relayCount++
			port, err = extractPublicPort(node.NetAddress)
			if err != nil {
				return
			}
			if !ports[port] {
				ports[port] = true
				portList = append(portList, strconv.Itoa(port))
			}
		}

		// See if the APIEndpoint is open to the public, and if so add it
		// Error means it's not valid/specified as public port
		port, apiPortErr := extractPublicPort(node.APIEndpoint)
		if apiPortErr != nil {
			if node.APIEndpoint != "" {
				fmt.Fprintf(os.Stdout, "(not publishing APIEndpoint '%s': %s)\n", node.APIEndpoint, apiPortErr)
			}
		} else {
			if !ports[port] {
				ports[port] = true
				portList = append(portList, strconv.Itoa(port))
			}
		}

		// See if any nodes expose a Dashboard port
		// Error means it's not valid/specified as public port
		port, dashPortErr := extractPublicPort(node.DashboardEndpoint)
		if dashPortErr != nil {
			if node.DashboardEndpoint != "" {
				fmt.Fprintf(os.Stdout, "(not publishing DashboardEndpoint '%s': %s)\n", node.DashboardEndpoint, dashPortErr)
			}
		} else {
			if !ports[port] {
				ports[port] = true
				portList = append(portList, strconv.Itoa(port))
			}
		}

		if node.EnableMetrics {
			metricsAddress := defaultConfig.NodeExporterListenAddress
			if node.MetricsURI != "" {
				metricsAddress = node.MetricsURI
			}

			shortVersion := metricsAddress
			i := strings.LastIndex(metricsAddress, ":")
			if i > 0 {
				shortVersion = metricsAddress[i:]
			}
			port, apiPortErr := extractPublicPort(shortVersion)
			if apiPortErr != nil {
				if node.MetricsURI != "" {
					fmt.Fprintf(os.Stdout, "(not publishing MetricsURI '%s': %s)\n", node.MetricsURI, apiPortErr)
				}
			} else {
				if !ports[port] {
					ports[port] = true
					portList = append(portList, strconv.Itoa(port))
				}
			}
		}
	}

	hostSpec.Name = host.Name
	hostSpec.Group = host.Group
	hostSpec.Provider = template.Provider
	hostSpec.Region = template.Region
	hostSpec.InstanceType = template.BaseConfiguration
	hostSpec.IncomingPorts = strings.Join(portList, ",")
	hostSpec.ProtectedPorts = "22"
	hostSpec.OutgoingPorts = "*"

	rootStorage := computeRootStorage(nodeCount, relayCount)
	ssdStorage := computeSSDStorage(nodeCount, relayCount)

	hostSpec.Configuration = cloudHostConfiguration{
		RootStorage: rootStorage,
		SSD2:        ssdStorage,
	}

	return
}

func extractPublicPort(address string) (port int, err error) {
	// To be exposed to the public, we expect it to bind to a specific port on any interface
	if address == "" || address[0] != ':' {
		return 0, fmt.Errorf("invalid public port specified (needs to be of format ':1234') - '%s'", address)
	}
	portAddress := address[1:]
	port, err = strconv.Atoi(portAddress)
	if err == nil && port <= 0 {
		err = fmt.Errorf("public port can't be zero - '%s'", address)
	}
	return
}

func computeRootStorage(nodeCount, relayCount int) int {
	// For now, we'll just use root storage -- assume short-lived instances
	// 10 per node should be good for a week (add relayCount * 0 so param is used)
	minGB := 10 + nodeCount*10 + (relayCount * 50)
	return minGB
}

func computeSSDStorage(nodeCount, relayCount int) int {
	// Zero for now.  Compute just so the params are used.
	return 0 * nodeCount * relayCount
}
