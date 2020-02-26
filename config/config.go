// Copyright (C) 2019-2020 Algorand, Inc.
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

package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/codecs"
)

// Devnet identifies the 'development network' use for development and not generally accessible publicly
const Devnet protocol.NetworkID = "devnet"

// Devtestnet identifies the 'development network for tests' use for running tests against development and not generally accessible publicly
const Devtestnet protocol.NetworkID = "devtestnet"

// Testnet identifies the publicly-available test network
const Testnet protocol.NetworkID = "testnet"

// Mainnet identifies the publicly-available real-money network
const Mainnet protocol.NetworkID = "mainnet"

// GenesisJSONFile is the name of the genesis.json file
const GenesisJSONFile = "genesis.json"

// Local holds the per-node-instance configuration settings for the protocol.
type Local struct {
	// Version tracks the current version of the defaults so we can migrate old -> new
	// This is specifically important whenever we decide to change the default value
	// for an existing parameter.
	Version uint32

	// environmental (may be overridden)
	// if true, does not garbage collect; also, replies to catchup requests
	Archival bool

	// gossipNode.go
	// how many peers to propagate to?
	GossipFanout  int
	NetAddress    string
	ReconnectTime time.Duration
	// what we should tell people to connect to
	PublicAddress string

	MaxConnectionsPerIP int

	// 0 == disable
	PeerPingPeriodSeconds int

	// for https serving
	TLSCertFile string
	TLSKeyFile  string

	// Logging
	BaseLoggerDebugLevel uint32
	// if this is 0, do not produce agreement.cadaver
	CadaverSizeTarget uint64

	// IncomingConnectionsLimit specifies the max number of long-lived incoming
	// connections.  0 means no connections allowed.  -1 is unbounded.
	IncomingConnectionsLimit int

	// BroadcastConnectionsLimit specifies the number of connections that
	// will receive broadcast (gossip) messages from this node.  If the
	// node has more connections than this number, it will send broadcasts
	// to the top connections by priority (outgoing connections first, then
	// by money held by peers based on their participation key).  0 means
	// no outgoing messages (not even transaction broadcasting to outgoing
	// peers).  -1 means unbounded (default).
	BroadcastConnectionsLimit int

	// AnnounceParticipationKey specifies that this node should announce its
	// participation key (with the largest stake) to its gossip peers.  This
	// allows peers to prioritize our connection, if necessary, in case of a
	// DoS attack.  Disabling this means that the peers will not have any
	// additional information to allow them to prioritize our connection.
	AnnounceParticipationKey bool

	// PriorityPeers specifies peer IP addresses that should always get
	// outgoing broadcast messages from this node.
	PriorityPeers map[string]bool

	// To make sure the algod process does not run out of FDs, algod ensures
	// that RLIMIT_NOFILE exceeds the max number of incoming connections (i.e.,
	// IncomingConnectionsLimit) by at least ReservedFDs.  ReservedFDs are meant
	// to leave room for short-lived FDs like DNS queries, SQLite files, etc.
	ReservedFDs uint64

	// local server
	// API endpoint address
	EndpointAddress string

	// timeouts passed to the rest http.Server implementation
	RestReadTimeoutSeconds  int
	RestWriteTimeoutSeconds int

	// SRV-based phonebook
	DNSBootstrapID string

	// Log file size limit in bytes
	LogSizeLimit uint64

	// text/template for creating log archive filename.
	// Available template vars:
	// Time at start of log: {{.Year}} {{.Month}} {{.Day}} {{.Hour}} {{.Minute}} {{.Second}}
	// Time at end of log: {{.EndYear}} {{.EndMonth}} {{.EndDay}} {{.EndHour}} {{.EndMinute}} {{.EndSecond}}
	//
	// If the filename ends with .gz or .bz2 it will be compressed.
	//
	// default: "node.archive.log" (no rotation, clobbers previous archive)
	LogArchiveName string

	// LogArchiveMaxAge will be parsed by time.ParseDuration().
	// Valid units are 's' seconds, 'm' minutes, 'h' hours
	LogArchiveMaxAge string

	// number of consecutive attempts to catchup after which we replace the peers we're connected to
	CatchupFailurePeerRefreshRate int

	// where should the node exporter listen for metrics
	NodeExporterListenAddress string

	// enable metric reporting flag
	EnableMetricReporting bool

	// enable top accounts reporting flag
	EnableTopAccountsReporting bool

	// enable agreement reporting flag. Currently only prints additional period events.
	EnableAgreementReporting bool

	// enable agreement timing metrics flag
	EnableAgreementTimeMetrics bool

	// The path to the node exporter.
	NodeExporterPath string

	// The fallback DNS resolver address that would be used if the system resolver would fail to retrieve SRV records
	FallbackDNSResolverAddress string

	// exponential increase factor of transaction pool's fee threshold, should always be 2 in production
	TxPoolExponentialIncreaseFactor uint64

	SuggestedFeeBlockHistory int

	// TxPoolSize is the number of transactions that fit in the transaction pool
	TxPoolSize int

	// number of seconds allowed for syncing transactions
	TxSyncTimeoutSeconds int64

	// number of seconds between transaction synchronizations
	TxSyncIntervalSeconds int64

	// the number of incoming message hashes buckets.
	IncomingMessageFilterBucketCount int

	// the size of each incoming message hash bucket.
	IncomingMessageFilterBucketSize int

	// the number of outgoing message hashes buckets.
	OutgoingMessageFilterBucketCount int

	// the size of each outgoing message hash bucket.
	OutgoingMessageFilterBucketSize int

	// enable the filtering of outgoing messages
	EnableOutgoingNetworkMessageFiltering bool

	// enable the filtering of incoming messages
	EnableIncomingMessageFilter bool

	// control enabling / disabling deadlock detection.
	// negative (-1) to disable, positive (1) to enable, 0 for default.
	DeadlockDetection int

	// Prefer to run algod Hosted (under algoh)
	// Observed by `goal` for now.
	RunHosted bool

	// The maximal number of blocks that catchup will fetch in parallel.
	// If less than Protocol.SeedLookback, then Protocol.SeedLookback will be used as to limit the catchup.
	CatchupParallelBlocks uint64

	// Generate AssembleBlockMetrics telemetry event
	EnableAssembleStats bool

	// Generate ProcessBlockMetrics telemetry event
	EnableProcessBlockStats bool

	// SuggestedFeeSlidingWindowSize is number of past blocks that will be considered in computing the suggested fee
	SuggestedFeeSlidingWindowSize uint32

	// the max size the sync server would return
	TxSyncServeResponseSize int

	// IsIndexerActive indicates whether to activate the indexer for fast retrieval of transactions
	// Note -- Indexer cannot operate on non Archival nodes
	IsIndexerActive bool

	// UseXForwardedForAddress indicates whether or not the node should use the X-Forwarded-For HTTP Header when
	// determining the source of a connection.  If used, it should be set to the string "X-Forwarded-For", unless the
	// proxy vendor provides another header field.  In the case of CloudFlare proxy, the "CF-Connecting-IP" header
	// field can be used.
	UseXForwardedForAddressField string

	// ForceRelayMessages indicates whether the network library relay messages even in the case that no NetAddress was specified.
	ForceRelayMessages bool

	// ConnectionsRateLimitingWindowSeconds is being used in conjunction with ConnectionsRateLimitingCount;
	// see ConnectionsRateLimitingCount description for further information. Providing a zero value
	// in this variable disables the connection rate limiting.
	ConnectionsRateLimitingWindowSeconds uint

	// ConnectionsRateLimitingCount is being used along with ConnectionsRateLimitingWindowSeconds to determine if
	// a connection request should be accepted or not. The gossip network examine all the incoming requests in the past
	// ConnectionsRateLimitingWindowSeconds seconds that share the same origin. If the total count exceed the ConnectionsRateLimitingCount
	// value, the connection is refused.
	ConnectionsRateLimitingCount uint

	// EnableRequestLogger enabled the logging of the incoming requests to the telemetry server.
	EnableRequestLogger bool

	// PeerConnectionsUpdateInterval defines the interval at which the peer connections information is being sent to the
	// telemetry ( when enabled ). Defined in seconds.
	PeerConnectionsUpdateInterval int

	// EnableProfiler enables the go pprof endpoints, should be false if
	// the algod api will be exposed to untrusted individuals
	EnableProfiler bool

	// TelemetryToLog records messages to node.log that are normally sent to remote event monitoring
	TelemetryToLog bool

	// DNSSecurityFlags instructs algod validating DNS responses.
	// Possible fla values
	// 0x00 - disabled
	// 0x01 (dnssecSRV) - validate SRV response
	// 0x02 (dnssecRelayAddr) - validate relays' names to addresses resolution
	// 0x04 (dnssecTelemetryAddr) - validate telemetry and metrics names to addresses resolution
	// ...
	DNSSecurityFlags uint32

	// EnablePingHandler controls whether the gossip node would respond to ping messages with a pong message.
	EnablePingHandler bool
}

// Filenames of config files within the configdir (e.g. ~/.algorand)

// ConfigFilename is the name of the config.json file where we store per-algod-instance settings
const ConfigFilename = "config.json"

// PhonebookFilename is the name of the phonebook configuration files - no longer used
const PhonebookFilename = "phonebook.json" // No longer used in product - still in tests

// LedgerFilenamePrefix is the prefix of the name of the ledger database files
const LedgerFilenamePrefix = "ledger"

// CrashFilename is the name of the agreement database file.
// It is used to recover from node crashes.
const CrashFilename = "crash.sqlite"

// ConfigurableConsensusProtocolsFilename defines a set of consensus prototocols that
// are to be loaded from the data directory ( if present ), to override the
// built-in supported consensus protocols.
const ConfigurableConsensusProtocolsFilename = "consensus.json"

// LoadConfigFromDisk returns a Local config structure based on merging the defaults
// with settings loaded from the config file from the custom dir.  If the custom file
// cannot be loaded, the default config is returned (with the error from loading the
// custom file).
func LoadConfigFromDisk(custom string) (c Local, err error) {
	return loadConfigFromFile(filepath.Join(custom, ConfigFilename))
}

func loadConfigFromFile(configFile string) (c Local, err error) {
	c = defaultLocal
	c.Version = 0 // Reset to 0 so we get the version from the loaded file.
	c, err = mergeConfigFromFile(configFile, c)
	if err != nil {
		return
	}

	// Migrate in case defaults were changed
	// If a config file does not have version, it is assumed to be zero.
	// All fields listed in migrate() might be changed if an actual value matches to default value from a previous version.
	c, err = migrate(c)
	return
}

// GetDefaultLocal returns a copy of the current defaultLocal config
func GetDefaultLocal() Local {
	return defaultLocal
}

func mergeConfigFromDir(root string, source Local) (Local, error) {
	return mergeConfigFromFile(filepath.Join(root, ConfigFilename), source)
}

func mergeConfigFromFile(configpath string, source Local) (Local, error) {
	f, err := os.Open(configpath)
	if err != nil {
		return source, err
	}
	defer f.Close()

	err = loadConfig(f, &source)

	// For now, all relays (listening for incoming connections) are also Archival
	// We can change this logic in the future, but it's currently the sanest default.
	if source.NetAddress != "" {
		source.Archival = true
	}

	return source, err
}

func loadConfig(reader io.Reader, config *Local) error {
	dec := json.NewDecoder(reader)
	return dec.Decode(config)
}

// DNSBootstrapArray returns an array of one or more DNS Bootstrap identifiers
func (cfg Local) DNSBootstrapArray(networkID protocol.NetworkID) (bootstrapArray []string) {
	dnsBootstrapString := cfg.DNSBootstrap(networkID)
	bootstrapArray = strings.Split(dnsBootstrapString, ";")
	return
}

// DNSBootstrap returns the network-specific DNSBootstrap identifier
func (cfg Local) DNSBootstrap(network protocol.NetworkID) string {
	// if user hasn't modified the default DNSBootstrapID in the configuration
	// file and we're targeting a devnet ( via genesis file ), we the
	// explicit devnet network bootstrap.
	if defaultLocal.DNSBootstrapID == cfg.DNSBootstrapID && network == Devnet {
		return "devnet.algodev.network"
	}
	return strings.Replace(cfg.DNSBootstrapID, "<network>", string(network), -1)
}

// SaveToDisk writes the Local settings into a root/ConfigFilename file
func (cfg Local) SaveToDisk(root string) error {
	configpath := filepath.Join(root, ConfigFilename)
	filename := os.ExpandEnv(configpath)
	return cfg.SaveToFile(filename)
}

// SaveToFile saves the config to a specific filename, allowing overriding the default name
func (cfg Local) SaveToFile(filename string) error {
	var alwaysInclude []string
	alwaysInclude = append(alwaysInclude, "Version")
	return codecs.SaveNonDefaultValuesToFile(filename, cfg, defaultLocal, alwaysInclude, true)
}

type phonebookBlackWhiteList struct {
	Include []string
}

// LoadPhonebook returns a phonebook loaded from the provided directory, if it exists.
// NOTE: We no longer use phonebook for anything but tests, but users should be able to use it
func LoadPhonebook(datadir string) ([]string, error) {
	var entries []string
	path := filepath.Join(datadir, PhonebookFilename)
	f, rootErr := os.Open(path)
	if rootErr != nil {
		if !os.IsNotExist(rootErr) {
			return nil, rootErr
		}
	} else {
		defer f.Close()

		phonebook := phonebookBlackWhiteList{}
		dec := json.NewDecoder(f)
		err := dec.Decode(&phonebook)
		if err != nil {
			return nil, errors.New("error decoding phonebook! got error: " + err.Error())
		}
		entries = phonebook.Include
	}

	// get an initial list of peers
	return entries, rootErr
}

// SavePhonebookToDisk writes the phonebook into a root/PhonebookFilename file
func SavePhonebookToDisk(entries []string, root string) error {
	configpath := filepath.Join(root, PhonebookFilename)
	f, err := os.OpenFile(os.ExpandEnv(configpath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		defer f.Close()
		err = savePhonebook(entries, f)
	}
	return err
}

func savePhonebook(entries []string, w io.Writer) error {
	pb := phonebookBlackWhiteList{
		Include: entries,
	}
	enc := codecs.NewFormattedJSONEncoder(w)
	return enc.Encode(pb)
}

var globalConfigFileRoot string

// GetConfigFilePath retrieves the full path to a configuration file
// These are global configurations - not specific to data-directory / network.
func GetConfigFilePath(file string) (string, error) {
	rootPath, err := GetGlobalConfigFileRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(rootPath, file), nil
}

// GetGlobalConfigFileRoot returns the current root folder for global configuration files.
// This will likely only change for tests.
func GetGlobalConfigFileRoot() (string, error) {
	var err error
	if globalConfigFileRoot == "" {
		globalConfigFileRoot, err = GetDefaultConfigFilePath()
		if err == nil {
			dirErr := os.Mkdir(globalConfigFileRoot, os.ModePerm)
			if !os.IsExist(dirErr) {
				err = dirErr
			}
		}
	}
	return globalConfigFileRoot, err
}

// SetGlobalConfigFileRoot allows overriding the root folder for global configuration files.
// It returns the current one so it can be restored, if desired.
// This will likely only change for tests.
func SetGlobalConfigFileRoot(rootPath string) string {
	currentRoot := globalConfigFileRoot
	globalConfigFileRoot = rootPath
	return currentRoot
}

// GetDefaultConfigFilePath retrieves the default directory for global (not per-instance) config files
// By default we store in ~/.algorand/.
// This will likely only change for tests.
func GetDefaultConfigFilePath() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	if currentUser.HomeDir == "" {
		return "", errors.New("GetDefaultConfigFilePath fail - current user has no home directory")
	}
	return filepath.Join(currentUser.HomeDir, ".algorand"), nil
}

const (
	dnssecSRV = 1 << iota
	dnssecRelayAddr
	dnssecTelemetryAddr
)

// DNSSecuritySRVEnforced returns true if SRV response verification enforced
func (cfg Local) DNSSecuritySRVEnforced() bool {
	return cfg.DNSSecurityFlags&dnssecSRV != 0
}

// DNSSecurityRelayAddrEnforced returns true if relay name to ip addr resolution enforced
func (cfg Local) DNSSecurityRelayAddrEnforced() bool {
	return cfg.DNSSecurityFlags&dnssecRelayAddr != 0
}

// DNSSecurityTelemeryAddrEnforced returns true if relay name to ip addr resolution enforced
func (cfg Local) DNSSecurityTelemeryAddrEnforced() bool {
	return cfg.DNSSecurityFlags&dnssecTelemetryAddr != 0
}
