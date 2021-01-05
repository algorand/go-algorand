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

// Package v1 defines models exposed by algod rest api
package v1

// NodeStatus contains the information about a node status
// swagger:model NodeStatus
type NodeStatus struct {
	// LastRound indicates the last round seen
	//
	// required: true
	LastRound uint64 `json:"lastRound"`

	// LastVersion indicates the last consensus version supported
	//
	// required: true
	LastVersion string `json:"lastConsensusVersion"`

	// NextVersion of consensus protocol to use
	//
	// required: true
	NextVersion string `json:"nextConsensusVersion"`

	// NextVersionRound is the round at which the next consensus version will apply
	//
	// required: true
	NextVersionRound uint64 `json:"nextConsensusVersionRound"`

	// NextVersionSupported indicates whether the next consensus version is supported by this node
	//
	// required: true
	NextVersionSupported bool `json:"nextConsensusVersionSupported"`

	// TimeSinceLastRound in nanoseconds
	//
	// required: true
	TimeSinceLastRound int64 `json:"timeSinceLastRound"`

	// CatchupTime in nanoseconds
	//
	// required: true
	CatchupTime int64 `json:"catchupTime"`

	// HasSyncedSinceStartup indicates whether a round has completed since startup
	// Required: true
	HasSyncedSinceStartup bool `json:"hasSyncedSinceStartup"`

	// StoppedAtUnsupportedRound indicates that the node does not support the new rounds and has stopped making progress
	//
	// Required: true
	StoppedAtUnsupportedRound bool `json:"stoppedAtUnsupportedRound"`
}

// TransactionID Description
// swagger:model transactionID
type TransactionID struct {
	// TxId is the string encoding of the transaction hash
	//
	// required: true
	TxID string `json:"txId"`
}

// Participation Description
// swagger:model Participation
type Participation struct { // Round and Address fields are redundant if Participation embedded in Account. Exclude for now.
	// ParticipationPK is the root participation public key (if any) currently registered for this round
	//
	// required: true
	// swagger:strfmt byte
	ParticipationPK []byte `json:"partpkb64"`

	// VRFPK is the selection public key (if any) currently registered for this round
	//
	// required: true
	// swagger:strfmt byte
	VRFPK []byte `json:"vrfpkb64"`

	// VoteFirst is the first round for which this participation is valid.
	//
	// required: true
	VoteFirst uint64 `json:"votefst"`

	// VoteLast is the last round for which this participation is valid.
	//
	// required: true
	VoteLast uint64 `json:"votelst"`

	// VoteKeyDilution is the number of subkeys in for each batch of participation keys.
	//
	// required: true
	VoteKeyDilution uint64 `json:"votekd"`
}

// TealValue represents a value stored in a TEAL key/value store. It includes
// type information to disambiguate empty values from each other.
//
// swagger: model TealValue
type TealValue struct {
	// Type is the type of the value, either "b" for a TEAL byte slice or
	// "u" for a TEAL uint
	//
	// required: true
	Type string `json:"t"`

	// Bytes is the value of a TEAL byte slice
	//
	// required: true
	Bytes string `json:"b,omitempty"`

	// Uint is the value of a TEAL uint
	//
	// required: true
	Uint uint64 `json:"u,omitempty"`
}

// AppParams stores the global information associated with the application,
// including its current logic, state schemas, and global state.
//
// swagger: model AppParams
type AppParams struct {
	// Creator is the creator of the application, whose account stores the
	// AppParams
	//
	// required: true
	Creator string `json:"creator,omitempty"`

	// ApprovalProgram is the logic that executes for each ApplicationCall
	// transaction besides those where OnCompletion == ClearStateOC. It can
	// read and write global state for the application, as well as
	// account-specific local state.
	//
	// required: true
	ApprovalProgram string `json:"approvprog"`

	// ClearStateProgram is the logic that executes for each ApplicationCall
	// transaction where OnCompletion == ClearStateOC. It can read and write
	// global state for the application, as well as account-specific local
	// state. However, it cannot reject the transaction.
	//
	// required: true
	ClearStateProgram string `json:"clearprog"`

	// LocalStateSchema sets limits on the number of strings and integers
	// that may be stored in an account's LocalState. for this application.
	// The larger these limits are, the larger minimum balance must be
	// maintained inside the account of any users who opt into this
	// application. The LocalStateSchema is immutable.
	//
	// require: true
	LocalStateSchema *StateSchema `json:"localschema"`

	// GlobalStateSchema sets limits on the number of strings and integers
	// that may be stored in the GlobalState. The larger these limits are,
	// the larger minimum balance must be maintained inside the creator's
	// account (in order to 'pay' for the state that can be used). The
	// GlobalStateSchema is immutable.
	//
	// require: true
	GlobalStateSchema *StateSchema `json:"globalschema"`

	// GlobalState stores global keys and values associated with this
	// application. It must respect the limits set by GlobalStateSchema.
	//
	// require: true
	GlobalState map[string]TealValue `json:"globalstate"`
}

// StateSchema represents a LocalStateSchema or GlobalStateSchema. These
// schemas determine how much storage may be used in a LocalState or
// GlobalState for an application. The more space used, the larger minimum
// balance must be maintained in the account holding the data.
//
// swagger: model StateSchema
type StateSchema struct {
	// NumUint is the maximum number of TEAL uints that may be stored in
	// the key/value store
	//
	// required: true
	NumUint uint64 `json:"uints"`

	// NumByteSlice is the maximum number of TEAL byte slices that may be
	// stored in the key/value store
	//
	// required: true
	NumByteSlice uint64 `json:"byteslices"`
}

// Application specifies both the unique identifier and the parameters for an
// application
//
// swagger:model Application
type Application struct {
	// AppIndex is the unique application identifier
	//
	// required: true
	AppIndex uint64 `json:"appidx"`

	// AppParams specifies the parameters of application referred to by AppIndex
	//
	// required: true
	AppParams AppParams `json:"appparams"`
}

// Account Description
// swagger:model Account
type Account struct {
	// Round indicates the round for which this information is relevant
	//
	// required: true
	Round uint64 `json:"round"`

	// Address indicates the account public key
	//
	// required: true
	Address string `json:"address"`

	// Amount indicates the total number of MicroAlgos in the account
	//
	// required: true
	Amount uint64 `json:"amount"`

	// PendingRewards specifies the amount of MicroAlgos of pending
	// rewards in this account.
	//
	// required: true
	PendingRewards uint64 `json:"pendingrewards"`

	// AmountWithoutPendingRewards specifies the amount of MicroAlgos in
	// the account, without the pending rewards.
	//
	// required: true
	AmountWithoutPendingRewards uint64 `json:"amountwithoutpendingrewards"`

	// Rewards indicates the total rewards of MicroAlgos the account has received, including pending rewards.
	//
	// required: true
	Rewards uint64 `json:"rewards"`

	// Status indicates the delegation status of the account's MicroAlgos
	// Offline - indicates that the associated account is delegated.
	// Online  - indicates that the associated account used as part of the delegation pool.
	// NotParticipating - indicates that the associated account is neither a delegator nor a delegate.
	//
	// required: true
	Status string `json:"status"`

	// Participation is the participation information currently associated with the account, if any.
	// This field is optional and may not be set even if participation information is registered.
	// In future REST API versions, this field may become required.
	//
	// required: false
	Participation *Participation `json:"participation,omitempty"`

	// AssetParams specifies the parameters of assets created by this account.
	//
	// required: false
	AssetParams map[uint64]AssetParams `json:"thisassettotal,omitempty"`

	// Assets specifies the holdings of assets by this account,
	// indexed by the asset ID.
	//
	// required: false
	Assets map[uint64]AssetHolding `json:"assets,omitempty"`

	// AppLocalStates is a map of local states for applications this
	// account has opted in to, as well as a copy of each application's
	// LocalStateSchema
	//
	// required: false
	AppLocalStates map[uint64]AppLocalState `json:"applocalstates,omitempty"`

	// AppParams is a map of application parameters for applications that
	// were created by this account. These parameters include the
	// application's global state map
	//
	// required: false
	AppParams map[uint64]AppParams `json:"appparams,omitempty"`
}

// AppLocalState holds the local key/value store of an application for an
// account that has opted in, as well as a copy of that application's
// LocalStateSchema
//
// swagger:model AppLocalState
type AppLocalState struct {
	// Schema is a copy of the application's LocalStateSchema
	Schema *StateSchema `json:"localschema"`

	// KeyValue is the key/value store representing the application's
	// local state in this account
	KeyValue map[string]TealValue `json:"localstate"`
}

// Asset specifies both the unique identifier and the parameters for an asset
//
// swagger:model Asset
type Asset struct {
	// AssetIndex is the unique asset identifier
	//
	// required: true
	AssetIndex uint64

	// AssetParams specifies the parameters of asset referred to by AssetIndex
	//
	// required: true
	AssetParams AssetParams
}

// AssetParams specifies the parameters for an asset.
// swagger:model AssetParams
type AssetParams struct {
	// Creator specifies the address that created this asset.
	// This is the address where the parameters for this asset
	// can be found, and also the address where unwanted asset
	// units can be sent in the worst case.
	//
	// required: true
	Creator string `json:"creator"`

	// Total specifies the total number of units of this asset.
	//
	// required: true
	Total uint64 `json:"total"`

	// Decimals specifies the number of digits to use after the decimal
	// point when displaying this asset. If 0, the asset is not divisible.
	// If 1, the base unit of the asset is in tenths. If 2, the base unit
	// of the asset is in hundredths, and so on.
	//
	// required: true
	Decimals uint32 `json:"decimals"`

	// DefaultFrozen specifies whether holdings in this asset
	// are frozen by default.
	//
	// required: false
	DefaultFrozen bool `json:"defaultfrozen"`

	// UnitName specifies the name of a unit of this asset,
	// as supplied by the creator.
	//
	// required: false
	UnitName string `json:"unitname,omitempty"`

	// AssetName specifies the name of this asset,
	// as supplied by the creator.
	//
	// required: false
	AssetName string `json:"assetname,omitempty"`

	// URL specifies a URL where more information about the asset can be
	// retrieved
	//
	// required: false
	URL string `json:"url,omitempty"`

	// MetadataHash specifies a commitment to some unspecified asset
	// metadata. The format of this metadata is up to the application.
	//
	// required: false
	// swagger:strfmt byte
	MetadataHash []byte `json:"metadatahash,omitempty"`

	// ManagerAddr specifies the address used to manage the keys of this
	// asset and to destroy it.
	//
	// required: false
	ManagerAddr string `json:"managerkey"`

	// ReserveAddr specifies the address holding reserve (non-minted)
	// units of this asset.
	//
	// required: false
	ReserveAddr string `json:"reserveaddr"`

	// FreezeAddr specifies the address used to freeze holdings of
	// this asset.  If empty, freezing is not permitted.
	//
	// required: false
	FreezeAddr string `json:"freezeaddr"`

	// ClawbackAddr specifies the address used to clawback holdings of
	// this asset.  If empty, clawback is not permitted.
	//
	// required: false
	ClawbackAddr string `json:"clawbackaddr"`
}

// AssetHolding specifies the holdings of a particular asset.
// swagger:model AssetHolding
type AssetHolding struct {
	// Creator specifies the address that created this asset.
	// This is the address where the parameters for this asset
	// can be found, and also the address where unwanted asset
	// units can be sent in the worst case.
	//
	// required: true
	Creator string `json:"creator"`

	// Amount specifies the number of units held.
	//
	// required: true
	Amount uint64 `json:"amount"`

	// Frozen specifies whether this holding is frozen.
	//
	// required: false
	Frozen bool `json:"frozen"`
}

// Transaction contains all fields common to all transactions and serves as an envelope to all transactions
// type
// swagger:model Transaction
type Transaction struct {
	// Type is the transaction type
	//
	// required: true
	Type string `json:"type"`

	// TxID is the transaction ID
	//
	// required: true
	TxID string `json:"tx"`

	// From is the sender's address
	//
	// required: true
	From string `json:"from"`

	// Fee is the transaction fee
	//
	// required: true
	Fee uint64 `json:"fee"`

	// FirstRound indicates the first valid round for this transaction
	//
	// required: true
	FirstRound uint64 `json:"first-round"`

	// LastRound indicates the last valid round for this transaction
	//
	// required: true
	LastRound uint64 `json:"last-round"`

	// Note is a free form data
	//
	// required: false
	// swagger:strfmt byte
	Note []byte `json:"noteb64,omitempty"`

	// Lease enforces mutual exclusion of transactions.  If this field is
	// nonzero, then once the transaction is confirmed, it acquires the
	// lease identified by the (Sender, Lease) pair of the transaction until
	// the LastValid round passes.  While this transaction possesses the
	// lease, no other transaction specifying this lease can be confirmed.
	//
	// required: false
	// swagger:strfmt byte
	Lease []byte `json:"lease,omitempty"`

	// ConfirmedRound indicates the block number this transaction appeared in
	//
	// required: false
	ConfirmedRound uint64 `json:"round"`

	// TransactionResults contains information about the side effects of a transaction
	//
	// required: false
	TransactionResults *TransactionResults `json:"txresults,omitempty"`

	// PoolError indicates the transaction was evicted from this node's transaction
	// pool (if non-empty).  A non-empty PoolError does not guarantee that the
	// transaction will never be committed; other nodes may not have evicted the
	// transaction and may attempt to commit it in the future.
	//
	// required: false
	PoolError string `json:"poolerror,omitempty"`

	// This is a list of all supported transactions.
	// To add another one, create a struct with XXXTransactionType and embed it here.
	// To prevent extraneous fields, all must have the "omitempty" tag.

	// Payment contains the additional fields for a payment transaction.
	//
	// required: false
	Payment *PaymentTransactionType `json:"payment,omitempty"`

	// Keyreg contains the additional fields for a keyreg transaction.
	//
	// required: false
	Keyreg *KeyregTransactionType `json:"keyreg,omitempty"`

	// AssetConfig contains the additional fields for an asset config transaction.
	//
	// required: false
	AssetConfig *AssetConfigTransactionType `json:"curcfg,omitempty"`

	// AssetTransfer contains the additional fields for an asset transfer transaction.
	//
	// required: false
	AssetTransfer *AssetTransferTransactionType `json:"curxfer,omitempty"`

	// AssetFreeze contains the additional fields for an asset freeze transaction.
	//
	// required: false
	AssetFreeze *AssetFreezeTransactionType `json:"curfrz,omitempty"`

	// ApplicationCall
	//
	// required: true
	ApplicationCall *ApplicationCallTransactionType `json:"app,omitempty"`

	// CompactCert
	//
	// required: true
	CompactCert *CompactCertTransactionType `json:"compactcert,omitempty"`

	// FromRewards is the amount of pending rewards applied to the From
	// account as part of this transaction.
	//
	// required: false
	FromRewards uint64 `json:"fromrewards"`

	// Genesis ID
	//
	// required: true
	GenesisID string `json:"genesisID"`

	// Genesis hash
	//
	// required: true
	// swagger:strfmt byte
	GenesisHash []byte `json:"genesishashb64"`

	// Group
	//
	// required: false
	// swagger:strfmt byte
	Group []byte `json:"group,omitempty"`
}

// PaymentTransactionType contains the additional fields for a payment Transaction
// swagger:model PaymentTransactionType
type PaymentTransactionType struct {
	// To is the receiver's address
	//
	// required: true
	To string `json:"to"`

	// CloseRemainderTo is the address the sender closed to
	//
	// required: false
	CloseRemainderTo string `json:"close,omitempty"`

	// CloseAmount is the amount sent to CloseRemainderTo, for committed transaction
	//
	// required: false
	CloseAmount uint64 `json:"closeamount,omitempty"`

	// Amount is the amount of MicroAlgos intended to be transferred
	//
	// required: true
	Amount uint64 `json:"amount"`

	// ToRewards is the amount of pending rewards applied to the To account
	// as part of this transaction.
	//
	// required: false
	ToRewards uint64 `json:"torewards"`

	// CloseRewards is the amount of pending rewards applied to the CloseRemainderTo
	// account as part of this transaction.
	//
	// required: false
	CloseRewards uint64 `json:"closerewards"`
}

// KeyregTransactionType contains the additional fields for a keyreg Transaction
// swagger:model KeyregTransactionType
type KeyregTransactionType struct {
	// VotePK is the participation public key used in key registration transactions
	//
	// required: false
	// swagger:strfmt byte
	VotePK []byte `json:"votekey"`

	// SelectionPK is the VRF public key used in key registration transactions
	//
	// required: false
	// swagger:strfmt byte
	SelectionPK []byte `json:"selkey"`

	// VoteFirst is the first round this participation key is valid
	//
	// required: false
	VoteFirst uint64 `json:"votefst"`

	// VoteLast is the last round this participation key is valid
	//
	// required: false
	VoteLast uint64 `json:"votelst"`

	// VoteKeyDilution is the dilution for the 2-level participation key
	//
	// required: false
	VoteKeyDilution uint64 `json:"votekd"`
}

// TransactionResults contains information about the side effects of a transaction
// swagger:model TransactionResults
type TransactionResults struct {
	// CreatedAssetIndex indicates the asset index of an asset created by this txn
	//
	// required: false
	CreatedAssetIndex uint64 `json:"createdasset,omitempty"`

	// CreatedAppIndex indicates the app index of an app created by this txn
	//
	// required: false
	CreatedAppIndex uint64 `json:"createdapp,omitempty"`
}

// AssetConfigTransactionType contains the additional fields for an asset config transaction
// swagger:model AssetConfigTransactionType
type AssetConfigTransactionType struct {
	// AssetID is the asset being configured (or empty if creating)
	//
	// required: false
	AssetID uint64 `json:"id"`

	// Params specifies the new asset parameters (or empty if deleting)
	//
	// required: false
	Params AssetParams `json:"params"`
}

// AssetTransferTransactionType contains the additional fields for an asset transfer transaction
// swagger:model AssetTransferTransactionType
type AssetTransferTransactionType struct {
	// AssetID is the asset being configured (or empty if creating)
	//
	// required: true
	AssetID uint64 `json:"id"`

	// Amount is the amount being transferred.
	//
	// required: true
	Amount uint64 `json:"amt"`

	// Sender is the source account (if using clawback).
	//
	// required: false
	Sender string `json:"snd"`

	// Receiver is the recipient account.
	//
	// required: true
	Receiver string `json:"rcv"`

	// CloseTo is the destination for remaining funds (if closing).
	//
	// required: false
	CloseTo string `json:"closeto"`
}

// AssetFreezeTransactionType contains the additional fields for an asset freeze transaction
// swagger:model AssetFreezeTransactionType
type AssetFreezeTransactionType struct {
	// AssetID is the asset being configured (or empty if creating)
	//
	// required: true
	AssetID uint64 `json:"id"`

	// Account specifies the account where the asset is being frozen or thawed.
	//
	// required: true
	Account string `json:"acct"`

	// NewFreezeStatus specifies the new freeze status.
	//
	// required: true
	NewFreezeStatus bool `json:"freeze"`
}

// ApplicationCallTransactionType contains the additional fields for an ApplicationCall transaction
// swagger:model ApplicationCallTransactionType
type ApplicationCallTransactionType struct {
	// ApplicationID is the application being interacted with, or 0 if
	// creating a new application.
	//
	// required: true
	ApplicationID uint64 `json:"id"`

	// Accounts lists the accounts (in addition to the sender) that may be
	// accessed from the application's ApprovalProgram and ClearStateProgram.
	//
	// required: true
	Accounts []string `json:"accounts"`

	// ForeignApps lists the applications (in addition to txn.ApplicationID)
	// whose global states may be accessed by this application's
	// ApprovalProgram and ClearStateProgram. The access is read-only.
	//
	// required: true
	ForeignApps []uint64 `json:"foreignapps"`

	// ForeignAssets lists the assets whose parameters may be accessed by
	// this application's ApprovalProgram and ClearStateProgram. The access
	// is read-only.
	//
	// required: true
	ForeignAssets []uint64 `json:"foreignassets"`

	// ApplicationArgs lists some transaction-specific arguments accessible
	// from application logic
	//
	// required: true
	ApplicationArgs []string `json:"appargs"`

	// ApprovalProgram determines whether or not this ApplicationCall
	// transaction will be approved or not. It does not execute when
	// OnCompletion == ClearStateOC, because clearing local state is always
	// allowed.
	//
	// required: true
	ApprovalProgram string `json:"approvprog,omitempty"`

	// ClearStateProgram executes when an ApplicationCall transaction
	// executes with OnCompletion == ClearStateOC. However, this program
	// may not reject the transaction (only update state). If this program
	//
	// required: true
	ClearStateProgram string `json:"clearprog,omitempty"`

	// GlobalStateSchema sets limits on the number of strings and integers
	// that may be stored in the GlobalState. The larger these limits are,
	// the larger minimum balance must be maintained inside the creator's
	// account (in order to 'pay' for the state that can be used). The
	// GlobalStateSchema is immutable.
	//
	// require: true
	GlobalStateSchema *StateSchema `json:"globalschema,omitempty"`

	// LocalStateSchema sets limits on the number of strings and integers
	// that may be stored in an account's LocalState. for this application.
	// The larger these limits are, the larger minimum balance must be
	// maintained inside the account of any users who opt into this
	// application. The LocalStateSchema is immutable.
	//
	// require: true
	LocalStateSchema *StateSchema `json:"localschema,omitempty"`

	// OnCompletion specifies what side effects this transaction will have
	// if it successfully makes it into a block.
	//
	// require: true
	OnCompletion string `json:"oncompletion"`
}

// CompactCertTransactionType contains the additional fields for a compact cert transaction
// swagger:model CompactCertTransactionType
type CompactCertTransactionType struct {
	// CertRound is the round whose block this compact cert refers to.
	//
	// required: true
	CertRound uint64 `json:"rnd"`

	// Cert is the msgpack encoding of the compact cert.
	//
	// required: true
	// swagger:strfmt byte
	Cert []byte `json:"cert"`
}

// TransactionList contains a list of transactions
// swagger:model TransactionList
type TransactionList struct {
	// TransactionList is a list of transactions
	//
	// required: true
	Transactions []Transaction `json:"transactions,omitempty"`
}

// AssetList contains a list of assets
// swagger:model AssetList
type AssetList struct {
	// Assets is a list of assets
	//
	// required: true
	Assets []Asset `json:"assets,omitempty"`
}

// TransactionFee contains the suggested fee
// swagger:model TransactionFee
type TransactionFee struct {
	// Fee is transaction fee
	// Fee is in units of micro-Algos per byte.
	// Fee may fall to zero but transactions must still have a fee of
	// at least MinTxnFee for the current network protocol.
	//
	// required: true
	Fee uint64 `json:"fee"`
}

// TransactionParams contains the parameters that help a client construct
// a new transaction.
// swagger:model TransactionParams
type TransactionParams struct {
	// Fee is the suggested transaction fee
	// Fee is in units of micro-Algos per byte.
	// Fee may fall to zero but transactions must still have a fee of
	// at least MinTxnFee for the current network protocol.
	//
	// required: true
	Fee uint64 `json:"fee"`

	// Genesis ID
	//
	// required: true
	GenesisID string `json:"genesisID"`

	// Genesis hash
	//
	// required: true
	// swagger:strfmt byte
	GenesisHash []byte `json:"genesishashb64"`

	// LastRound indicates the last round seen
	//
	// required: true
	LastRound uint64 `json:"lastRound"`

	// ConsensusVersion indicates the consensus protocol version
	// as of LastRound.
	//
	// required: true
	ConsensusVersion string `json:"consensusVersion"`

	// The minimum transaction fee (not per byte) required for the
	// txn to validate for the current network protocol.
	//
	// required: false
	MinTxnFee uint64 `json:"minFee"`
}

// RawResponse is fulfilled by responses that should not be decoded as msgpack
type RawResponse interface {
	SetBytes([]byte)
}

// RawBlock represents an encoded msgpack block
// swagger:model RawBlock
// swagger:strfmt byte
type RawBlock []byte

// SetBytes fulfills the RawResponse interface on RawBlock
func (rb *RawBlock) SetBytes(b []byte) {
	*rb = b
}

// Block contains a block information
// swagger:model Block
type Block struct {
	// Hash is the current block hash
	//
	// required: true
	Hash string `json:"hash"`

	// PreviousBlockHash is the previous block hash
	//
	// required: true
	PreviousBlockHash string `json:"previousBlockHash"`

	// Seed is the sortition seed
	//
	// required: true
	Seed string `json:"seed"`

	// Proposer is the address of this block proposer
	//
	// required: true
	Proposer string `json:"proposer"`

	// Round is the current round on which this block was appended to the chain
	//
	// required: true
	Round uint64 `json:"round"`

	// Period is the period on which the block was confirmed
	//
	// required: true
	Period uint64 `json:"period"`

	// TransactionsRoot authenticates the set of transactions appearing in the block.
	// More specifically, it's the root of a merkle tree whose leaves are the block's Txids, in lexicographic order.
	// For the empty block, it's 0.
	// Note that the TxnRoot does not authenticate the signatures on the transactions, only the transactions themselves.
	// Two blocks with the same transactions but in a different order and with different signatures will have the same TxnRoot.
	//
	// required: true
	TransactionsRoot string `json:"txnRoot"`

	// RewardsLevel specifies how many rewards, in MicroAlgos,
	// have been distributed to each config.Protocol.RewardUnit
	// of MicroAlgos since genesis.
	RewardsLevel uint64 `json:"reward"`

	// The number of new MicroAlgos added to the participation stake from rewards at the next round.
	RewardsRate uint64 `json:"rate"`

	// The number of leftover MicroAlgos after the distribution of RewardsRate/rewardUnits
	// MicroAlgos for every reward unit in the next round.
	RewardsResidue uint64 `json:"frac"`

	// Transactions is the list of transactions in this block
	Transactions TransactionList `json:"txns"`

	// TimeStamp in seconds since epoch
	//
	// required: true
	Timestamp int64 `json:"timestamp"`

	UpgradeState
	UpgradeVote

	// CompactCertVoters is the root of the merkle tree of voters for compact certs.
	//
	// required: true
	// swagger:strfmt byte
	CompactCertVoters []byte `json:"compactCertVoters"`

	// CompactCertVotersTotal is the total amount of microalgos held by the voters in
	// the CompactCertVoters merkle tree.
	//
	// required: true
	CompactCertVotersTotal uint64 `json:"compactCertVotersTotal"`

	// CompactCertLastRound is the last round for which a compact certificate has
	// been recorded using a compactcert transaction.
	//
	// required: true
	CompactCertLastRound uint64 `json:"compactCertLastRound"`
}

// UpgradeState contains the information about a current state of an upgrade
// swagger:model UpgradeState
type UpgradeState struct {
	// CurrentProtocol is a string that represents the current protocol
	//
	// required: true
	CurrentProtocol string `json:"currentProtocol"`

	// NextProtocol is a string that represents the next proposed protocol
	//
	// required: true
	NextProtocol string `json:"nextProtocol"`

	// NextProtocolApprovals is the number of blocks which approved the protocol upgrade
	//
	// required: true
	NextProtocolApprovals uint64 `json:"nextProtocolApprovals"`

	// NextProtocolVoteBefore is the deadline round for this protocol upgrade (No votes will be consider after this round)
	//
	// required: true
	NextProtocolVoteBefore uint64 `json:"nextProtocolVoteBefore"`

	// NextProtocolSwitchOn is the round on which the protocol upgrade will take effect
	//
	// required: true
	NextProtocolSwitchOn uint64 `json:"nextProtocolSwitchOn"`
}

// UpgradeVote represents the vote of the block proposer with respect to protocol upgrades.
// swagger:model UpgradeVote
type UpgradeVote struct {
	// UpgradePropose indicates a proposed upgrade
	//
	// required: true
	UpgradePropose string `json:"upgradePropose"`

	// UpgradeApprove indicates a yes vote for the current proposal
	//
	// required: true
	UpgradeApprove bool `json:"upgradeApprove"`
}

// Supply represents the current supply of MicroAlgos in the system
// swagger:model Supply
type Supply struct {
	// Round
	//
	// required: true
	Round uint64 `json:"round"`

	// TotalMoney
	//
	// required: true
	TotalMoney uint64 `json:"totalMoney"`

	// OnlineMoney
	//
	// required: true
	OnlineMoney uint64 `json:"onlineMoney"`
}

// PendingTransactions represents a potentially truncated list of transactions currently in the
// node's transaction pool.
// swagger:model PendingTransactions
type PendingTransactions struct {
	// TruncatedTxns
	// required: true
	TruncatedTxns TransactionList `json:"truncatedTxns"`
	// TotalTxns
	// required: true
	TotalTxns uint64 `json:"totalTxns"`
}
