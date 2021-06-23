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

package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/algorand/go-algorand/protocol"
)

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
	// overridden in the account state.
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

	// EnableFeePooling specifies that the sum of the fees in a
	// group must exceed one MinTxnFee per Txn, rather than check that
	// each Txn has a MinFee.
	EnableFeePooling bool

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

	// time for nodes to wait for block proposal headers for period > 0, value should be set to 2 * SmallLambda
	AgreementFilterTimeout time.Duration
	// time for nodes to wait for block proposal headers for period = 0, value should be configured to suit best case
	// critical path
	AgreementFilterTimeoutPeriod0 time.Duration

	FastRecoveryLambda    time.Duration // time between fast recovery attempts
	FastPartitionRecovery bool          // set when fast partition recovery is enabled

	// how to commit to the payset: flat or merkle tree
	PaysetCommit PaysetCommitType

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
	// note: if FixTransactionLeases is not set, the transaction
	// leases supported are faulty; specifically, they do not
	// enforce exclusion correctly when the FirstValid of
	// transactions do not match.
	SupportTransactionLeases bool
	FixTransactionLeases     bool

	// 0 for no support, otherwise highest version supported
	LogicSigVersion uint64

	// len(LogicSig.Logic) + len(LogicSig.Args[*]) must be less than this
	LogicSigMaxSize uint64

	// sum of estimated op cost must be less than this
	LogicSigMaxCost uint64

	// max decimal precision for assets
	MaxAssetDecimals uint32

	// SupportRekeying indicates support for account rekeying (the RekeyTo and AuthAddr fields)
	SupportRekeying bool

	// application support
	Application bool

	// max number of ApplicationArgs for an ApplicationCall transaction
	MaxAppArgs int

	// max sum([len(arg) for arg in txn.ApplicationArgs])
	MaxAppTotalArgLen int

	// maximum byte len of application approval program or clear state
	// When MaxExtraAppProgramPages > 0, this is the size of those pages.
	// So two "extra pages" would mean 3*MaxAppProgramLen bytes are available.
	MaxAppProgramLen int

	// maximum total length of an application's programs (approval + clear state)
	// When MaxExtraAppProgramPages > 0, this is the size of those pages.
	// So two "extra pages" would mean 3*MaxAppTotalProgramLen bytes are available.
	MaxAppTotalProgramLen int

	// extra length for application program in pages. A page is MaxAppProgramLen bytes
	MaxExtraAppProgramPages int

	// maximum number of accounts in the ApplicationCall Accounts field.
	// this determines, in part, the maximum number of balance records
	// accessed by a single transaction
	MaxAppTxnAccounts int

	// maximum number of app ids in the ApplicationCall ForeignApps field.
	// these are the only applications besides the called application for
	// which global state may be read in the transaction
	MaxAppTxnForeignApps int

	// maximum number of asset ids in the ApplicationCall ForeignAssets
	// field. these are the only assets for which the asset parameters may
	// be read in the transaction
	MaxAppTxnForeignAssets int

	// maximum number of "foreign references" (accounts, asa, app)
	// that can be attached to a single app call.
	MaxAppTotalTxnReferences int

	// maximum cost of application approval program or clear state program
	MaxAppProgramCost int

	// maximum length of a key used in an application's global or local
	// key/value store
	MaxAppKeyLen int

	// maximum length of a bytes value used in an application's global or
	// local key/value store
	MaxAppBytesValueLen int

	// maximum sum of the lengths of the key and value of one app state entry
	MaxAppSumKeyValueLens int

	// maximum number of applications a single account can create and store
	// AppParams for at once
	MaxAppsCreated int

	// maximum number of applications a single account can opt in to and
	// store AppLocalState for at once
	MaxAppsOptedIn int

	// flat MinBalance requirement for creating a single application and
	// storing its AppParams
	AppFlatParamsMinBalance uint64

	// flat MinBalance requirement for opting in to a single application
	// and storing its AppLocalState
	AppFlatOptInMinBalance uint64

	// MinBalance requirement per key/value entry in LocalState or
	// GlobalState key/value stores, regardless of value type
	SchemaMinBalancePerEntry uint64

	// MinBalance requirement (in addition to SchemaMinBalancePerEntry) for
	// integer values stored in LocalState or GlobalState key/value stores
	SchemaUintMinBalance uint64

	// MinBalance requirement (in addition to SchemaMinBalancePerEntry) for
	// []byte values stored in LocalState or GlobalState key/value stores
	SchemaBytesMinBalance uint64

	// maximum number of total key/value pairs allowed by a given
	// LocalStateSchema (and therefore allowed in LocalState)
	MaxLocalSchemaEntries uint64

	// maximum number of total key/value pairs allowed by a given
	// GlobalStateSchema (and therefore allowed in GlobalState)
	MaxGlobalSchemaEntries uint64

	// maximum total minimum balance requirement for an account, used
	// to limit the maximum size of a single balance record
	MaximumMinimumBalance uint64

	// CompactCertRounds defines the frequency with which compact
	// certificates are generated.  Every round that is a multiple
	// of CompactCertRounds, the block header will include a Merkle
	// commitment to the set of online accounts (that can vote after
	// another CompactCertRounds rounds), and that block will be signed
	// (forming a compact certificate) by the voters from the previous
	// such Merkle tree commitment.  A value of zero means no compact
	// certificates.
	CompactCertRounds uint64

	// CompactCertTopVoters is a bound on how many online accounts get to
	// participate in forming the compact certificate, by including the
	// top CompactCertTopVoters accounts (by normalized balance) into the
	// Merkle commitment.
	CompactCertTopVoters uint64

	// CompactCertVotersLookback is the number of blocks we skip before
	// publishing a Merkle commitment to the online accounts.  Namely,
	// if block number N contains a Merkle commitment to the online
	// accounts (which, incidentally, means N%CompactCertRounds=0),
	// then the balances reflected in that commitment must come from
	// block N-CompactCertVotersLookback.  This gives each node some
	// time (CompactCertVotersLookback blocks worth of time) to
	// construct this Merkle tree, so as to avoid placing the
	// construction of this Merkle tree (and obtaining the requisite
	// accounts and balances) in the critical path.
	CompactCertVotersLookback uint64

	// CompactCertWeightThreshold specifies the fraction of top voters weight
	// that must sign the message (block header) for security.  The compact
	// certificate ensures this threshold holds; however, forming a valid
	// compact certificate requires a somewhat higher number of signatures,
	// and the more signatures are collected, the smaller the compact cert
	// can be.
	//
	// This threshold can be thought of as the maximum fraction of
	// malicious weight that compact certificates defend against.
	//
	// The threshold is computed as CompactCertWeightThreshold/(1<<32).
	CompactCertWeightThreshold uint32

	// CompactCertSecKQ is the security parameter (k+q) for the compact
	// certificate scheme.
	CompactCertSecKQ uint64

	// EnableAssetCloseAmount adds an extra field to the ApplyData. The field contains the amount of the remaining
	// asset that were sent to the close-to address.
	EnableAssetCloseAmount bool

	// update the initial rewards rate calculation to take the reward pool minimum balance into account
	InitialRewardsRateCalculation bool

	// NoEmptyLocalDeltas updates how ApplyDelta.EvalDelta.LocalDeltas are stored
	NoEmptyLocalDeltas bool

	// EnableKeyregCoherencyCheck enable the following extra checks on key registration transactions:
	// 1. checking that [VotePK/SelectionPK/VoteKeyDilution] are all set or all clear.
	// 2. checking that the VoteFirst is less or equal to VoteLast.
	// 3. checking that in the case of going offline, both the VoteFirst and VoteLast are clear.
	// 4. checking that in the case of going online the VoteLast is non-zero and greater then the current network round.
	// 5. checking that in the case of going online the VoteFirst is less or equal to the LastValid+1.
	// 6. checking that in the case of going online the VoteFirst is less or equal to the next network round.
	EnableKeyregCoherencyCheck bool
}

// PaysetCommitType enumerates possible ways for the block header to commit to
// the set of transactions in the block.
type PaysetCommitType int

const (
	// PaysetCommitUnsupported is the zero value, reflecting the fact
	// that some early protocols used a Merkle tree to commit to the
	// transactions in a way that we no longer support.
	PaysetCommitUnsupported PaysetCommitType = iota

	// PaysetCommitFlat hashes the entire payset array.
	PaysetCommitFlat

	// PaysetCommitMerkle uses merklearray to commit to the payset.
	PaysetCommitMerkle
)

// ConsensusProtocols defines a set of supported protocol versions and their
// corresponding parameters.
type ConsensusProtocols map[protocol.ConsensusVersion]ConsensusParams

// Consensus tracks the protocol-level settings for different versions of the
// consensus protocol.
var Consensus ConsensusProtocols

// MaxVoteThreshold is the largest threshold for a bundle over all supported
// consensus protocols, used for decoding purposes.
var MaxVoteThreshold int

// MaxEvalDeltaAccounts is the largest number of accounts that may appear in
// an eval delta, used for decoding purposes.
var MaxEvalDeltaAccounts int

// MaxStateDeltaKeys is the largest number of key/value pairs that may appear
// in a StateDelta, used for decoding purposes.
var MaxStateDeltaKeys int

// MaxLogicSigMaxSize is the largest logical signature appear in any of the supported
// protocols, used for decoding purposes.
var MaxLogicSigMaxSize int

// MaxTxnNoteBytes is the largest supported nodes field array size supported by any
// of the consensus protocols. used for decoding purposes.
var MaxTxnNoteBytes int

// MaxTxGroupSize is the largest supported number of transactions per transaction group supported by any
// of the consensus protocols. used for decoding purposes.
var MaxTxGroupSize int

// MaxAppProgramLen is the largest supported app program size supported by any
// of the consensus protocols. used for decoding purposes.
var MaxAppProgramLen int

// MaxBytesKeyValueLen is a maximum length of key or value across all protocols.
// used for decoding purposes.
var MaxBytesKeyValueLen int

// MaxExtraAppProgramLen is the maximum extra app program length supported by any
// of the consensus protocols. used for decoding purposes.
var MaxExtraAppProgramLen int

// MaxAvailableAppProgramLen is the largest supported app program size include the extra pages
//supported supported by any of the consensus protocols. used for decoding purposes.
var MaxAvailableAppProgramLen int

func checkSetMax(value int, curMax *int) {
	if value > *curMax {
		*curMax = value
	}
}

// checkSetAllocBounds sets some global variables used during msgpack decoding
// to enforce memory allocation limits. The values should be generous to
// prevent correctness bugs, but not so large that DoS attacks are trivial
func checkSetAllocBounds(p ConsensusParams) {
	checkSetMax(int(p.SoftCommitteeThreshold), &MaxVoteThreshold)
	checkSetMax(int(p.CertCommitteeThreshold), &MaxVoteThreshold)
	checkSetMax(int(p.NextCommitteeThreshold), &MaxVoteThreshold)
	checkSetMax(int(p.LateCommitteeThreshold), &MaxVoteThreshold)
	checkSetMax(int(p.RedoCommitteeThreshold), &MaxVoteThreshold)
	checkSetMax(int(p.DownCommitteeThreshold), &MaxVoteThreshold)

	// These bounds could be tighter, but since these values are just to
	// prevent DoS, setting them to be the maximum number of allowed
	// executed TEAL instructions should be fine (order of ~1000)
	checkSetMax(p.MaxAppProgramLen, &MaxStateDeltaKeys)
	checkSetMax(p.MaxAppProgramLen, &MaxEvalDeltaAccounts)
	checkSetMax(p.MaxAppProgramLen, &MaxAppProgramLen)
	checkSetMax(int(p.LogicSigMaxSize), &MaxLogicSigMaxSize)
	checkSetMax(p.MaxTxnNoteBytes, &MaxTxnNoteBytes)
	checkSetMax(p.MaxTxGroupSize, &MaxTxGroupSize)
	// MaxBytesKeyValueLen is max of MaxAppKeyLen and MaxAppBytesValueLen
	checkSetMax(p.MaxAppKeyLen, &MaxBytesKeyValueLen)
	checkSetMax(p.MaxAppBytesValueLen, &MaxBytesKeyValueLen)
	checkSetMax(p.MaxExtraAppProgramPages, &MaxExtraAppProgramLen)
	// MaxAvailableAppProgramLen is the max of supported app program size
	MaxAvailableAppProgramLen = MaxAppProgramLen * (1 + MaxExtraAppProgramLen)
}

// SaveConfigurableConsensus saves the configurable protocols file to the provided data directory.
// if the params contains zero protocols, the existing consensus.json file will be removed if exists.
func SaveConfigurableConsensus(dataDirectory string, params ConsensusProtocols) error {
	consensusProtocolPath := filepath.Join(dataDirectory, ConfigurableConsensusProtocolsFilename)

	if len(params) == 0 {
		// we have no consensus params to write. In this case, just delete the existing file
		// ( if any )
		err := os.Remove(consensusProtocolPath)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
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
		// Set allocation limits
		for _, p := range Consensus {
			checkSetAllocBounds(p)
		}
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
			return Consensus, nil
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

		AgreementFilterTimeout:        4 * time.Second,
		AgreementFilterTimeoutPeriod0: 4 * time.Second,

		FastRecoveryLambda: 5 * time.Minute,

		SeedLookback:        2,
		SeedRefreshInterval: 100,

		MaxBalLookback: 320,

		MaxTxGroupSize: 1,
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
	v11.PaysetCommit = PaysetCommitFlat
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
	Consensus[protocol.ConsensusV21] = v21
	// v20 can be upgraded to v21.
	v20.ApprovedUpgrades[protocol.ConsensusV21] = 0

	// v22 is an upgrade which allows tuning the number of rounds to wait to execute upgrades.
	v22 := v21
	v22.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	v22.MinUpgradeWaitRounds = 10000
	v22.MaxUpgradeWaitRounds = 150000
	Consensus[protocol.ConsensusV22] = v22

	// v23 is an upgrade which fixes the behavior of leases so that
	// it conforms with the intended spec.
	v23 := v22
	v23.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	v23.FixTransactionLeases = true
	Consensus[protocol.ConsensusV23] = v23
	// v22 can be upgraded to v23.
	v22.ApprovedUpgrades[protocol.ConsensusV23] = 10000
	// v21 can be upgraded to v23.
	v21.ApprovedUpgrades[protocol.ConsensusV23] = 0

	// v24 is the stateful teal and rekeying upgrade
	v24 := v23
	v24.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	v24.LogicSigVersion = 2

	// Enable application support
	v24.Application = true

	// Enable rekeying
	v24.SupportRekeying = true

	// 100.1 Algos (MinBalance for creating 1,000 assets)
	v24.MaximumMinimumBalance = 100100000

	v24.MaxAppArgs = 16
	v24.MaxAppTotalArgLen = 2048
	v24.MaxAppProgramLen = 1024
	v24.MaxAppTotalProgramLen = 2048 // No effect until v28, when MaxAppProgramLen increased
	v24.MaxAppKeyLen = 64
	v24.MaxAppBytesValueLen = 64
	v24.MaxAppSumKeyValueLens = 128 // Set here to have no effect until MaxAppBytesValueLen increases

	// 0.1 Algos (Same min balance cost as an Asset)
	v24.AppFlatParamsMinBalance = 100000
	v24.AppFlatOptInMinBalance = 100000

	// Can look up Sender + 4 other balance records per Application txn
	v24.MaxAppTxnAccounts = 4

	// Can look up 2 other app creator balance records to see global state
	v24.MaxAppTxnForeignApps = 2

	// Can look up 2 assets to see asset parameters
	v24.MaxAppTxnForeignAssets = 2

	// Intended to have no effect in v24 (it's set to accounts +
	// asas + apps). In later vers, it allows increasing the
	// individual limits while maintaining same max references.
	v24.MaxAppTotalTxnReferences = 8

	// 64 byte keys @ ~333 microAlgos/byte + delta
	v24.SchemaMinBalancePerEntry = 25000

	// 9 bytes @ ~333 microAlgos/byte + delta
	v24.SchemaUintMinBalance = 3500

	// 64 byte values @ ~333 microAlgos/byte + delta
	v24.SchemaBytesMinBalance = 25000

	// Maximum number of key/value pairs per local key/value store
	v24.MaxLocalSchemaEntries = 16

	// Maximum number of key/value pairs per global key/value store
	v24.MaxGlobalSchemaEntries = 64

	// Maximum cost of ApprovalProgram/ClearStateProgram
	v24.MaxAppProgramCost = 700

	// Maximum number of apps a single account can create
	v24.MaxAppsCreated = 10

	// Maximum number of apps a single account can opt into
	v24.MaxAppsOptedIn = 10
	Consensus[protocol.ConsensusV24] = v24

	// v23 can be upgraded to v24, with an update delay of 7 days ( see calculation above )
	v23.ApprovedUpgrades[protocol.ConsensusV24] = 140000

	// v25 enables AssetCloseAmount in the ApplyData
	v25 := v24
	v25.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	// Enable AssetCloseAmount field
	v25.EnableAssetCloseAmount = true
	Consensus[protocol.ConsensusV25] = v25

	// v26 adds support for teal3
	v26 := v25
	v26.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	// Enable the InitialRewardsRateCalculation fix
	v26.InitialRewardsRateCalculation = true

	// Enable transaction Merkle tree.
	v26.PaysetCommit = PaysetCommitMerkle

	// Enable teal3
	v26.LogicSigVersion = 3

	Consensus[protocol.ConsensusV26] = v26

	// v25 or v24 can be upgraded to v26, with an update delay of 7 days ( see calculation above )
	v25.ApprovedUpgrades[protocol.ConsensusV26] = 140000
	v24.ApprovedUpgrades[protocol.ConsensusV26] = 140000

	// v27 updates ApplyDelta.EvalDelta.LocalDeltas format
	v27 := v26
	v27.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	// Enable the ApplyDelta.EvalDelta.LocalDeltas fix
	v27.NoEmptyLocalDeltas = true

	Consensus[protocol.ConsensusV27] = v27

	// v26 can be upgraded to v27, with an update delay of 3 days
	// 60279 = (3 * 24 * 60 * 60 / 4.3)
	// for the sake of future manual calculations, we'll round that down
	// a bit :
	v26.ApprovedUpgrades[protocol.ConsensusV27] = 60000

	// v28 introduces new TEAL features, larger program size, fee pooling and longer asset max URL
	v28 := v27
	v28.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	// Enable TEAL 4
	v28.LogicSigVersion = 4
	// Enable support for larger app program size
	v28.MaxExtraAppProgramPages = 3
	v28.MaxAppProgramLen = 2048
	// Increase asset URL length to allow for IPFS URLs
	v28.MaxAssetURLBytes = 96
	// Let the bytes value take more space. Key+Value is still limited to 128
	v28.MaxAppBytesValueLen = 128

	// Individual limits raised
	v28.MaxAppTxnForeignApps = 8
	v28.MaxAppTxnForeignAssets = 8

	// MaxAppTxnAccounts has not been raised yet.  It is already
	// higher (4) and there is a multiplicative effect in
	// "reachability" between accounts and creatables, so we
	// retain 4 x 4 as worst case.

	v28.EnableFeePooling = true
	v28.EnableKeyregCoherencyCheck = true

	Consensus[protocol.ConsensusV28] = v28

	// v27 can be upgraded to v28, with an update delay of 7 days ( see calculation above )
	v27.ApprovedUpgrades[protocol.ConsensusV28] = 140000

	// ConsensusFuture is used to test features that are implemented
	// but not yet released in a production protocol version.
	vFuture := v28
	vFuture.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	// FilterTimeout for period 0 should take a new optimized, configured value, need to revisit this later
	vFuture.AgreementFilterTimeoutPeriod0 = 4 * time.Second

	// Enable compact certificates.
	vFuture.CompactCertRounds = 128
	vFuture.CompactCertTopVoters = 1024 * 1024
	vFuture.CompactCertVotersLookback = 16
	vFuture.CompactCertWeightThreshold = (1 << 32) * 30 / 100
	vFuture.CompactCertSecKQ = 128

	Consensus[protocol.ConsensusFuture] = vFuture
}

// Global defines global Algorand protocol parameters which should not be overridden.
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

func init() {
	Consensus = make(ConsensusProtocols)

	initConsensusProtocols()

	// Set allocation limits
	for _, p := range Consensus {
		checkSetAllocBounds(p)
	}
}
