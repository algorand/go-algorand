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

package bounds

/* The bounds package is intended to hold conservative bounds on the sizes of
   various messages.  Many cannot be static, because they depend on consensus
   parameters. They are set at runtime iterating over every consensus version
   and selecting the largest bound.  This allows msgpack parsing to safely
   reject anything that NO consensus version would allow.
*/

// MaxVoteThreshold is the largest threshold for a bundle over all supported
// consensus protocols, used for decoding purposes.
var MaxVoteThreshold int

// MaxEvalDeltaAccounts is the largest number of accounts that may appear in an
// eval delta, used for decoding purposes.
var MaxEvalDeltaAccounts int

// MaxStateDeltaKeys is the largest number of key/value pairs that may appear in
// a StateDelta, used for decoding purposes.
var MaxStateDeltaKeys int

// MaxLogCalls is the highest allowable log messages that may appear in any
// version, used only for decoding purposes. Never decrease this value.
var MaxLogCalls int

// MaxInnerTransactionsPerDelta is the maximum number of inner transactions in
// one EvalDelta
var MaxInnerTransactionsPerDelta int

// MaxLogicSigMaxSize is the largest logical signature appear in any of the
// supported protocols, used for decoding purposes.
var MaxLogicSigMaxSize int

// MaxTxnNoteBytes is the largest supported nodes field array size supported by
// any of the consensus protocols. used for decoding purposes.
var MaxTxnNoteBytes int

// MaxTxGroupSize is the largest supported number of transactions per
// transaction group supported by any of the consensus protocols. used for
// decoding purposes.
var MaxTxGroupSize int

// MaxAppProgramLen is the largest supported app program size supported by any
// of the consensus protocols. used for decoding purposes.
var MaxAppProgramLen int

// MaxBytesKeyValueLen is a maximum length of key or value across all protocols.
// used for decoding purposes.
var MaxBytesKeyValueLen int

// MaxExtraAppProgramLen is the maximum extra app program length supported by
// any of the consensus protocols. used for decoding purposes.
var MaxExtraAppProgramLen int

// MaxAvailableAppProgramLen is the largest supported app program size including
// the extra pages supported by any of the consensus protocols. used for
// decoding purposes.
var MaxAvailableAppProgramLen int

// MaxProposedExpiredOnlineAccounts is the maximum number of online accounts
// that a proposer can take offline for having expired voting keys.
var MaxProposedExpiredOnlineAccounts int

// MaxMarkAbsent is the maximum number of online accounts that a proposer can
// suspend for not proposing "lately"
var MaxMarkAbsent int

// MaxAppTotalArgLen is the maximum number of bytes across all arguments of an
// application max sum([len(arg) for arg in txn.ApplicationArgs])
var MaxAppTotalArgLen int

// MaxAssetNameBytes is the maximum asset name length in bytes
var MaxAssetNameBytes int

// MaxAssetUnitNameBytes is the maximum asset unit name length in bytes
var MaxAssetUnitNameBytes int

// MaxAssetURLBytes is the maximum asset URL length in bytes
var MaxAssetURLBytes int

// MaxAppBytesValueLen is the maximum length of a bytes value used in an
// application's global or local key/value store
var MaxAppBytesValueLen int

// MaxAppBytesKeyLen is the maximum length of a key used in an application's
// global or local key/value store
var MaxAppBytesKeyLen int

// StateProofTopVoters is a bound on how many online accounts get to participate
// in forming the state proof, by including the top StateProofTopVoters accounts
// (by normalized balance) into the vector commitment.
var StateProofTopVoters int

// MaxTxnBytesPerBlock determines the maximum number of bytes that transactions
// can take up in a block.  Specifically, the sum of the lengths of encodings of
// each transaction in a block must not exceed MaxTxnBytesPerBlock.
var MaxTxnBytesPerBlock int

// MaxAppTxnForeignApps is the max number of foreign apps per txn across all consensus versions
var MaxAppTxnForeignApps int

// MaxEvalDeltaTotalLogSize is the maximum size of the sum of all log sizes in a single eval delta.
const MaxEvalDeltaTotalLogSize = 1024

// MaxGenesisIDLen is the maximum length of the genesis ID set for purpose of
// setting allocbounds on structs containing GenesisID and for purposes of
// calculating MaxSize functions on those types. Current value is larger than
// the existing network IDs and the ones used in testing
const MaxGenesisIDLen = 128

// EncodedMaxAssetsPerAccount is the decoder limit of number of assets stored
// per account.  it's being verified by the unit test
// TestEncodedAccountAllocationBounds to align with
// config.Consensus[protocol.ConsensusCurrentVersion].MaxAssetsPerAccount; note
// that the decoded parameter is used only for protecting the decoder against
// malicious encoded account data stream.  protocol-specific contents would be
// tested once the decoding is complete.
const EncodedMaxAssetsPerAccount = 1024

// EncodedMaxAppLocalStates is the decoder limit for number of opted-in apps in a single account.
// It is verified in TestEncodedAccountAllocationBounds to align with
// config.Consensus[protocol.ConsensusCurrentVersion].MaxAppsOptedIn
const EncodedMaxAppLocalStates = 64

// EncodedMaxAppParams is the decoder limit for number of created apps in a single account.
// It is verified in TestEncodedAccountAllocationBounds to align with
// config.Consensus[protocol.ConsensusCurrentVersion].MaxAppsCreated
const EncodedMaxAppParams = 64

// EncodedMaxKeyValueEntries is the decoder limit for the length of a key/value store.
// It is verified in TestEncodedAccountAllocationBounds to align with
// config.Consensus[protocol.ConsensusCurrentVersion].MaxLocalSchemaEntries and
// config.Consensus[protocol.ConsensusCurrentVersion].MaxGlobalSchemaEntries
const EncodedMaxKeyValueEntries = 1024

// MaxConsensusVersionLen must be larger than any URL length of any consensus
// version (which is currently URL+hash=89)
const MaxConsensusVersionLen = 128
