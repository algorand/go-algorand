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
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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

// Global defines global Algorand protocol parameters which should not be overriden.
type Global struct {
	SmallLambda time.Duration // min amount of time to wait for leader's credential (i.e., time to propagate one credential)
	BigLambda   time.Duration // max amount of time to wait for leader's proposal (i.e., time to propagate one block)
}

// Protocol holds the global configuration settings for the agreement protocol,
// initialized with our current defaults. This is used across all nodes we create.
var Protocol = Global{
	SmallLambda: 2000 * time.Millisecond,
	BigLambda:   15000 * time.Millisecond,
}

// ConsensusParams specifies settings that might vary based on the
// particular version of the consensus protocol.
type ConsensusParams struct {
	// Consensus protocol upgrades.  Votes for upgrades are collected for
	// UpgradeVoteRounds.  If the number of positive votes is over
	// UpgradeThreshold, the proposal is accepted.
	//
	// UpgradeVoteRounds needs to be long enough to collect an
	// accurate sample of participants, and UpgradeThreshold needs
	// to be high enough to ensure that there are sufficient participants
	// after the upgrade.
	//
	// A consensus protocol upgrade may specify the delay between its
	// acceptance and its execution.  This gives clients time to notify
	// users.  This delay is specified by the upgrade proposer and must
	// be between MinUpgradeWaitRounds and MaxUpgradeWaitRounds (inclusive)
	// in the old protocol's parameters.  Note that these parameters refer
	// to the representation of the delay in a block rather than the actual
	// delay: if the specified delay is zero, it is equivalent to
	// DefaultUpgradeWaitRounds.
	//
	// The maximum length of a consensus version string is
	// MaxVersionStringLen.
	UpgradeVoteRounds        uint64
	UpgradeThreshold         uint64
	DefaultUpgradeWaitRounds uint64
	MinUpgradeWaitRounds     uint64
	MaxUpgradeWaitRounds     uint64
	MaxVersionStringLen      int

	// MaxTxnBytesPerBlock determines the maximum number of bytes
	// that transactions can take up in a block.  Specifically,
	// the sum of the lengths of encodings of each transaction
	// in a block must not exceed MaxTxnBytesPerBlock.
	MaxTxnBytesPerBlock int

	// MaxTxnBytesPerBlock is the maximum size of a transaction's Note field.
	MaxTxnNoteBytes int

	// MaxTxnLife is how long a transaction can be live for:
	// the maximum difference between LastValid and FirstValid.
	//
	// Note that in a protocol upgrade, the ledger must first be upgraded
	// to hold more past blocks for this value to be raised.
	MaxTxnLife uint64

	// ApprovedUpgrades describes the upgrade proposals that this protocol
	// implementation will vote for, along with their delay value
	// (in rounds).  A delay value of zero is the same as a delay of
	// DefaultUpgradeWaitRounds.
	ApprovedUpgrades map[protocol.ConsensusVersion]uint64

	// SupportGenesisHash indicates support for the GenesisHash
	// fields in transactions (and requires them in blocks).
	SupportGenesisHash bool

	// RequireGenesisHash indicates that GenesisHash must be present
	// in every transaction.
	RequireGenesisHash bool

	// DefaultKeyDilution specifies the granularity of top-level ephemeral
	// keys. KeyDilution is the number of second-level keys in each batch,
	// signed by a top-level "batch" key.  The default value can be
	// overriden in the account state.
	DefaultKeyDilution uint64

	// MinBalance specifies the minimum balance that can appear in
	// an account.  To spend money below MinBalance requires issuing
	// an account-closing transaction, which transfers all of the
	// money from the account, and deletes the account state.
	MinBalance uint64

	// MinTxnFee specifies the minimum fee allowed on a transaction.
	// A minimum fee is necessary to prevent DoS. In some sense this is
	// a way of making the spender subsidize the cost of storing this transaction.
	MinTxnFee uint64

	// RewardUnit specifies the number of MicroAlgos corresponding to one reward
	// unit.
	//
	// Rewards are received by whole reward units.  Fractions of
	// RewardUnits do not receive rewards.
	RewardUnit uint64

	// RewardsRateRefreshInterval is the number of rounds after which the
	// rewards level is recomputed for the next RewardsRateRefreshInterval rounds.
	RewardsRateRefreshInterval uint64

	// seed-related parameters
	SeedLookback        uint64 // how many blocks back we use seeds from in sortition. delta_s in the spec
	SeedRefreshInterval uint64 // how often an old block hash is mixed into the seed. delta_r in the spec

	// ledger retention policy
	MaxBalLookback uint64 // (current round - MaxBalLookback) is the oldest round the ledger must answer balance queries for

	// sortition threshold factors
	NumProposers           uint64
	SoftCommitteeSize      uint64
	SoftCommitteeThreshold uint64
	CertCommitteeSize      uint64
	CertCommitteeThreshold uint64
	NextCommitteeSize      uint64 // for any non-FPR votes >= deadline step, committee sizes and thresholds are constant
	NextCommitteeThreshold uint64
	LateCommitteeSize      uint64
	LateCommitteeThreshold uint64
	RedoCommitteeSize      uint64
	RedoCommitteeThreshold uint64
	DownCommitteeSize      uint64
	DownCommitteeThreshold uint64

	FastRecoveryLambda    time.Duration // time between fast recovery attempts
	FastPartitionRecovery bool          // set when fast partition recovery is enabled

	// commit to payset using a hash of entire payset,
	// instead of txid merkle tree
	PaysetCommitFlat bool

	MaxTimestampIncrement int64 // maximum time between timestamps on successive blocks

	// support for the efficient encoding in SignedTxnInBlock
	SupportSignedTxnInBlock bool

	// force the FeeSink address to be non-participating in the genesis balances.
	ForceNonParticipatingFeeSink bool

	// support for ApplyData in SignedTxnInBlock
	ApplyData bool

	// track reward distributions in ApplyData
	RewardsInApplyData bool

	// domain-separated credentials
	CredentialDomainSeparationEnabled bool

	// support for transactions that mark an account non-participating
	SupportBecomeNonParticipatingTransactions bool

	// fix the rewards calculation by avoiding subtracting too much from the rewards pool
	PendingResidueRewards bool

	// asset support
	Asset bool

	// max number of assets per account
	MaxAssetsPerAccount int

	// max length of asset name
	MaxAssetNameBytes int

	// max length of asset unit name
	MaxAssetUnitNameBytes int

	// max length of asset url
	MaxAssetURLBytes int

	// support sequential transaction counter TxnCounter
	TxnCounter bool

	// transaction groups
	SupportTxGroups bool

	// max group size
	MaxTxGroupSize int

	// support for transaction leases
	SupportTransactionLeases bool

	// 0 for no support, otherwise highest version supported
	LogicSigVersion uint64

	// len(LogicSig.Logic) + len(LogicSig.Args[*]) must be less than this
	LogicSigMaxSize uint64

	// sum of estimated op cost must be less than this
	LogicSigMaxCost uint64

	// max decimal precision for assets
	MaxAssetDecimals uint32

	// whether to use the old buggy Credential.lowestOutput function
	// TODO(upgrade): Please remove as soon as the upgrade goes through
	UseBuggyProposalLowestOutput bool
}

// ConsensusProtocols defines a set of supported protocols versions, and their corresponding
// parameters
type ConsensusProtocols map[protocol.ConsensusVersion]ConsensusParams

// Consensus tracks the protocol-level settings for different versions of the
// consensus protocol.
var Consensus ConsensusProtocols

func init() {
	Consensus = make(ConsensusProtocols)

	initConsensusProtocols()

	// Allow tuning SmallLambda for faster consensus in single-machine e2e
	// tests.  Useful for development.  This might make sense to fold into
	// a protocol-version-specific setting, once we move SmallLambda into
	// ConsensusParams.
	algoSmallLambda, err := strconv.ParseInt(os.Getenv("ALGOSMALLLAMBDAMSEC"), 10, 64)
	if err == nil {
		Protocol.SmallLambda = time.Duration(algoSmallLambda) * time.Millisecond
	}
}

// SaveConfigurableConsensus saves the configurable protocols file to the provided data directory.
func SaveConfigurableConsensus(dataDirectory string, params ConsensusProtocols) error {
	consensusProtocolPath := filepath.Join(dataDirectory, ConfigurableConsensusProtocolsFilename)

	encodedConsensusParams, err := json.Marshal(params)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(consensusProtocolPath, encodedConsensusParams, 0644)
	return err
}

// DeepCopy creates a deep copy of a consensus protocols map.
func (cp ConsensusProtocols) DeepCopy() ConsensusProtocols {
	staticConsensus := make(ConsensusProtocols)
	for consensusVersion, consensusParams := range cp {
		// recreate the ApprovedUpgrades map since we don't want to modify the original one.
		if consensusParams.ApprovedUpgrades != nil {
			newApprovedUpgrades := make(map[protocol.ConsensusVersion]uint64)
			for ver, when := range consensusParams.ApprovedUpgrades {
				newApprovedUpgrades[ver] = when
			}
			consensusParams.ApprovedUpgrades = newApprovedUpgrades
		}
		staticConsensus[consensusVersion] = consensusParams
	}
	return staticConsensus
}

// Merge merges a configurable consensus ontop of the existing consensus protocol and return
// a new consensus protocol without modify any of the incoming structures.
func (cp ConsensusProtocols) Merge(configurableConsensus ConsensusProtocols) ConsensusProtocols {
	staticConsensus := cp.DeepCopy()

	for consensusVersion, consensusParams := range configurableConsensus {
		if consensusParams.ApprovedUpgrades == nil {
			// if we were provided with an empty ConsensusParams, delete the existing reference to this consensus version
			for cVer, cParam := range staticConsensus {
				if cVer == consensusVersion {
					delete(staticConsensus, cVer)
				} else if _, has := cParam.ApprovedUpgrades[consensusVersion]; has {
					// delete upgrade to deleted version
					delete(cParam.ApprovedUpgrades, consensusVersion)
				}
			}
		} else {
			// need to add/update entry
			staticConsensus[consensusVersion] = consensusParams
		}
	}

	return staticConsensus
}

// LoadConfigurableConsensusProtocols loads the configurable protocols from the data directroy
func LoadConfigurableConsensusProtocols(dataDirectory string) error {
	newConsensus, err := PreloadConfigurableConsensusProtocols(dataDirectory)
	if err != nil {
		return err
	}
	if newConsensus != nil {
		Consensus = newConsensus
	}
	return nil
}

// PreloadConfigurableConsensusProtocols loads the configurable protocols from the data directroy
// and merge it with a copy of the Consensus map. Then, it returns it to the caller.
func PreloadConfigurableConsensusProtocols(dataDirectory string) (ConsensusProtocols, error) {
	consensusProtocolPath := filepath.Join(dataDirectory, ConfigurableConsensusProtocolsFilename)
	file, err := os.Open(consensusProtocolPath)

	if err != nil {
		if os.IsNotExist(err) {
			// this file is not required, only optional. if it's missing, no harm is done.
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	configurableConsensus := make(ConsensusProtocols)

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&configurableConsensus)
	if err != nil {
		return nil, err
	}
	return Consensus.Merge(configurableConsensus), nil
}

func initConsensusProtocols() {
	// WARNING: copying a ConsensusParams by value into a new variable
	// does not copy the ApprovedUpgrades map.  Make sure that each new
	// ConsensusParams structure gets a fresh ApprovedUpgrades map.

	// Base consensus protocol version, v7.
	v7 := ConsensusParams{
		UpgradeVoteRounds:        10000,
		UpgradeThreshold:         9000,
		DefaultUpgradeWaitRounds: 10000,
		MaxVersionStringLen:      64,

		MinBalance:          10000,
		MinTxnFee:           1000,
		MaxTxnLife:          1000,
		MaxTxnNoteBytes:     1024,
		MaxTxnBytesPerBlock: 1000000,
		DefaultKeyDilution:  10000,

		MaxTimestampIncrement: 25,

		RewardUnit:                 1e6,
		RewardsRateRefreshInterval: 5e5,

		ApprovedUpgrades: map[protocol.ConsensusVersion]uint64{},

		NumProposers:           30,
		SoftCommitteeSize:      2500,
		SoftCommitteeThreshold: 1870,
		CertCommitteeSize:      1000,
		CertCommitteeThreshold: 720,
		NextCommitteeSize:      10000,
		NextCommitteeThreshold: 7750,
		LateCommitteeSize:      10000,
		LateCommitteeThreshold: 7750,
		RedoCommitteeSize:      10000,
		RedoCommitteeThreshold: 7750,
		DownCommitteeSize:      10000,
		DownCommitteeThreshold: 7750,

		FastRecoveryLambda: 5 * time.Minute,

		SeedLookback:        2,
		SeedRefreshInterval: 100,

		MaxBalLookback: 320,

		MaxTxGroupSize:               1,
		UseBuggyProposalLowestOutput: true, // TODO(upgrade): Please remove as soon as the upgrade goes through
	}

	v7.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV7] = v7

	// v8 uses parameters and a seed derivation policy (the "twin seeds") from Georgios' new analysis
	v8 := v7

	v8.SeedRefreshInterval = 80
	v8.NumProposers = 9
	v8.SoftCommitteeSize = 2990
	v8.SoftCommitteeThreshold = 2267
	v8.CertCommitteeSize = 1500
	v8.CertCommitteeThreshold = 1112
	v8.NextCommitteeSize = 5000
	v8.NextCommitteeThreshold = 3838
	v8.LateCommitteeSize = 5000
	v8.LateCommitteeThreshold = 3838
	v8.RedoCommitteeSize = 5000
	v8.RedoCommitteeThreshold = 3838
	v8.DownCommitteeSize = 5000
	v8.DownCommitteeThreshold = 3838

	v8.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV8] = v8

	// v7 can be upgraded to v8.
	v7.ApprovedUpgrades[protocol.ConsensusV8] = 0

	// v9 increases the minimum balance to 100,000 microAlgos.
	v9 := v8
	v9.MinBalance = 100000
	v9.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV9] = v9

	// v8 can be upgraded to v9.
	v8.ApprovedUpgrades[protocol.ConsensusV9] = 0

	// v10 introduces fast partition recovery (and also raises NumProposers).
	v10 := v9
	v10.FastPartitionRecovery = true
	v10.NumProposers = 20
	v10.LateCommitteeSize = 500
	v10.LateCommitteeThreshold = 320
	v10.RedoCommitteeSize = 2400
	v10.RedoCommitteeThreshold = 1768
	v10.DownCommitteeSize = 6000
	v10.DownCommitteeThreshold = 4560
	v10.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV10] = v10

	// v9 can be upgraded to v10.
	v9.ApprovedUpgrades[protocol.ConsensusV10] = 0

	// v11 introduces SignedTxnInBlock.
	v11 := v10
	v11.SupportSignedTxnInBlock = true
	v11.PaysetCommitFlat = true
	v11.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV11] = v11

	// v10 can be upgraded to v11.
	v10.ApprovedUpgrades[protocol.ConsensusV11] = 0

	// v12 increases the maximum length of a version string.
	v12 := v11
	v12.MaxVersionStringLen = 128
	v12.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV12] = v12

	// v11 can be upgraded to v12.
	v11.ApprovedUpgrades[protocol.ConsensusV12] = 0

	// v13 makes the consensus version a meaningful string.
	v13 := v12
	v13.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV13] = v13

	// v12 can be upgraded to v13.
	v12.ApprovedUpgrades[protocol.ConsensusV13] = 0

	// v14 introduces tracking of closing amounts in ApplyData, and enables
	// GenesisHash in transactions.
	v14 := v13
	v14.ApplyData = true
	v14.SupportGenesisHash = true
	v14.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV14] = v14

	// v13 can be upgraded to v14.
	v13.ApprovedUpgrades[protocol.ConsensusV14] = 0

	// v15 introduces tracking of reward distributions in ApplyData.
	v15 := v14
	v15.RewardsInApplyData = true
	v15.ForceNonParticipatingFeeSink = true
	v15.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV15] = v15

	// v14 can be upgraded to v15.
	v14.ApprovedUpgrades[protocol.ConsensusV15] = 0

	// v16 fixes domain separation in credentials.
	v16 := v15
	v16.CredentialDomainSeparationEnabled = true
	v16.RequireGenesisHash = true
	v16.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV16] = v16

	// v15 can be upgraded to v16.
	v15.ApprovedUpgrades[protocol.ConsensusV16] = 0

	// ConsensusV17 points to 'final' spec commit
	v17 := v16
	v17.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	Consensus[protocol.ConsensusV17] = v17

	// v16 can be upgraded to v17.
	v16.ApprovedUpgrades[protocol.ConsensusV17] = 0

	// ConsensusV18 points to reward calculation spec commit
	v18 := v17
	v18.PendingResidueRewards = true
	v18.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	v18.TxnCounter = true
	v18.Asset = true
	v18.LogicSigVersion = 1
	v18.LogicSigMaxSize = 1000
	v18.LogicSigMaxCost = 20000
	v18.MaxAssetsPerAccount = 1000
	v18.SupportTxGroups = true
	v18.MaxTxGroupSize = 16
	v18.SupportTransactionLeases = true
	v18.SupportBecomeNonParticipatingTransactions = true
	v18.MaxAssetNameBytes = 32
	v18.MaxAssetUnitNameBytes = 8
	v18.MaxAssetURLBytes = 32
	Consensus[protocol.ConsensusV18] = v18

	// ConsensusV19 is the official spec commit ( teal, assets, group tx )
	v19 := v18
	v19.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	Consensus[protocol.ConsensusV19] = v19

	// v18 can be upgraded to v19.
	v18.ApprovedUpgrades[protocol.ConsensusV19] = 0
	// v17 can be upgraded to v19.
	v17.ApprovedUpgrades[protocol.ConsensusV19] = 0

	// v20 points to adding the precision to the assets.
	v20 := v19
	v20.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	v20.MaxAssetDecimals = 19
	// we want to adjust the upgrade time to be roughly one week.
	// one week, in term of rounds would be:
	// 140651 = (7 * 24 * 60 * 60 / 4.3)
	// for the sake of future manual calculations, we'll round that down
	// a bit :
	v20.DefaultUpgradeWaitRounds = 140000
	Consensus[protocol.ConsensusV20] = v20

	// v19 can be upgraded to v20.
	v19.ApprovedUpgrades[protocol.ConsensusV20] = 0

	// v21 fixes a bug in Credential.lowestOutput that would cause larger accounts to be selected to propose disproportionately more often than small accounts
	v21 := v20
	v21.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	v21.UseBuggyProposalLowestOutput = false // TODO(upgrade): Please remove this line as soon as the protocol upgrade goes through
	Consensus[protocol.ConsensusV21] = v21
	// v20 can be upgraded to v21.
	v20.ApprovedUpgrades[protocol.ConsensusV21] = 0

	// ConsensusFuture is used to test features that are implemented
	// but not yet released in a production protocol version.
	vFuture := v21
	vFuture.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	vFuture.MinUpgradeWaitRounds = 10000
	vFuture.MaxUpgradeWaitRounds = 150000
	Consensus[protocol.ConsensusFuture] = vFuture
}

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
