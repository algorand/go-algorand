// Copyright (C) 2019 Algorand, Inc.
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
	Participation Participation `json:"participation,omitempty"`
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
	Note []byte `json:"noteb64"`

	// ConfirmedRound indicates the block number this transaction appeared in
	//
	// required: false
	ConfirmedRound uint64 `json:"round"`

	// PoolError indicates the transaction was evicted from this node's transaction
	// pool (if non-empty).  A non-empty PoolError does not guarantee that the
	// transaction will never be committed; other nodes may not have evicted the
	// transaction and may attempt to commit it in the future.
	//
	// required: false
	PoolError string `json:"poolerror"`

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
	CloseRemainderTo string `json:"close"`

	// CloseAmount is the amount sent to CloseRemainderTo, for committed transaction
	//
	// required: false
	CloseAmount uint64 `json:"closeamount"`

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

// TransactionList contains a list of transactions
// swagger:model TransactionList
type TransactionList struct {
	// TransactionList is a list of transactions
	//
	// required: true
	Transactions []Transaction `json:"transactions,omitempty"`
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
