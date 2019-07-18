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

// Package models defines models used by an algod rest client
//
// IF YOU MODIFY THIS FILE: IMPORTANT
// In practice, this is straight up copied from /v1/models/model.go. It is duplicated
// from internal model code, to maintain the internal/external client encapsulation.
// It does flatten some embedded structs, however.
// No client should depend on any package in v1.
//
// We could use a swagger-generated client/models instead. However, the swagger
// generated client comes with a ton of dependencies and overhead, so we are
// sticking with a hard-coded internal approach.
package models

// Account Description
// swagger:model Account
type Account struct {
	// Round indicates the round for which this information is relevant
	//
	// required: true
	Round uint64 `json:"round"`

	// Address indicates the account public key
	// Required: true
	Address string `json:"address"`

	// Amount indicates the total number of MicroAlgos in the account,
	// including not-yet-claimed (pending) rewards.
	// Required: true
	Amount uint64 `json:"amount"`

	// PendingRewards specifies the amount of MicroAlgos of pending
	// rewards in this account.
	// Required: true
	PendingRewards uint64 `json:"pendingrewards"`

	// AmountWithoutPendingRewards specifies the amount of MicroAlgos in
	// the account, without the pending rewards.
	// Required: true
	AmountWithoutPendingRewards uint64 `json:"amountwithoutpendingrewards"`

	// Rewards indicates the total rewards of MicroAlgos the account has received
	//
	// required: true
	Rewards uint64 `json:"rewards"`

	// Status indicates the delegation status of the account's MicroAlgos
	// Offline - indicates that the associated account is delegated.
	// Online  - indicates that the associated account used as part of the delegation pool.
	// NotParticipating - indicates that the associated account is neither a delegator nor a delegate.
	// Required: true
	Status string `json:"status"`
}

// Block contains a block information
// swagger:model Block
type Block struct {

	// CurrentProtocol is a string that represents the current protocol
	// Required: true
	CurrentProtocol string `json:"currentProtocol"`

	// Hash is the current block hash
	// Required: true
	Hash string `json:"hash"`

	// NextProtocol is a string that represents the next proposed protocol
	// Required: true
	NextProtocol string `json:"nextProtocol"`

	// NextProtocolApprovals is the number of blocks which approved the protocol upgrade
	// Required: true
	NextProtocolApprovals uint64 `json:"nextProtocolApprovals"`

	// NextProtocolSwitchOn is the round on which the protocol upgrade will take effect
	// Required: true
	NextProtocolSwitchOn uint64 `json:"nextProtocolSwitchOn"`

	// NextProtocolVoteBefore is the deadline round for this protocol upgrade (No votes will be consider after this round)
	// Required: true
	NextProtocolVoteBefore uint64 `json:"nextProtocolVoteBefore"`

	// Period is the period on which the block was confirmed
	// Required: true
	Period uint64 `json:"period"`

	// PreviousBlockHash is the previous block hash
	// Required: true
	PreviousBlockHash string `json:"previousBlockHash"`

	// Proposer is the address of this block proposer
	// Required: true
	Proposer string `json:"proposer"`

	// Round is the current round on which this block was appended to the chain
	// Required: true
	Round uint64 `json:"round"`

	// Seed is the sortition seed
	// Required: true
	Seed string `json:"seed"`

	// TimeStamp in seconds since epoch
	// Required: true
	Timestamp int64 `json:"timestamp"`

	// TransactionsRoot authenticates the set of transactions appearing in the block.
	// More specifically, it's the root of a merkle tree whose leaves are the block's Txids, in lexicographic order.
	// For the empty block, it's 0.
	// Note that the TxnRoot does not authenticate the signatures on the transactions, only the transactions themselves.
	// Two blocks with the same transactions but in a different order and with different signatures will have the same TxnRoot.
	// Required: true
	TransactionsRoot string `json:"txnRoot"`

	// RewardsLevel specifies how many rewards, in MicroAlgos,
	// have been distributed to each config.Protocol.RewardUnit
	// of MicroAlgos since genesis.
	// Required: true
	RewardsLevel uint64 `json:"reward"`

	// The number of new MicroAlgos added to the participation stake from rewards at the next round.
	// Required: true
	RewardsRate uint64 `json:"rate"`

	// The number of leftover MicroAlgos after the distribution of RewardsRate/rewardUnits
	// MicroAlgos for every reward unit in the next round.
	// Required: true
	RewardsResidue uint64 `json:"frac"`

	// UpgradeApprove indicates a yes vote for the current proposal
	// Required: true
	UpgradeApprove *bool `json:"upgradeApprove"`

	// UpgradePropose indicates a proposed upgrade
	// Required: true
	UpgradePropose string `json:"upgradePropose"`

	// txns
	Txns TransactionList `json:"txns,omitempty"`
}

// NodeStatus contains the information about a node status
// swagger:model NodeStatus
type NodeStatus struct {

	// CatchupTime in nanoseconds
	// Required: true
	CatchupTime int64 `json:"catchupTime"`

	// LastRound indicates the last round seen
	// Required: true
	LastRound uint64 `json:"lastRound"`

	// LastVersion indicates the last consensus version supported
	// Required: true
	LastVersion string `json:"lastConsensusVersion"`

	// NextVersion of consensus protocol to use
	// Required: true
	NextVersion string `json:"nextConsensusVersion"`

	// NextVersionRound is the round at which the next consensus version will apply
	// Required: true
	NextVersionRound uint64 `json:"nextConsensusVersionRound"`

	// NextVersionSupported indicates whether the next consensus version is supported by this node
	// Required: true
	NextVersionSupported bool `json:"nextConsensusVersionSupported"`

	// TimeSinceLastRound in nanoseconds
	// Required: true
	TimeSinceLastRound int64 `json:"timeSinceLastRound"`

	// HasSyncedSinceStartup indicates whether a round has completed since startup
	// Required: true
	HasSyncedSinceStartup bool `json:"hasSyncedSinceStartup"`
}

// PaymentTransactionType contains the additional fields for a payment Transaction
// swagger:model PaymentTransactionType
type PaymentTransactionType struct {

	// Amount is the amount of MicroAlgos intended to be transferred
	// Required: true
	Amount uint64 `json:"amount"`

	// To is the receiver's address
	// Required: true
	To string `json:"to"`

	// CloseRemainderTo is the address that receives the remainder of the
	// account balance, if the transaction is closing the account.
	// Required: false
	CloseRemainderTo string `json:"close,omitempty"`

	// CloseAmount is the amount transferred to CloseRemainderTo, if
	// this transaction was confirmed.
	// Required: false
	CloseAmount uint64 `json:"closeamount,omitempty"`

	// ToRewards is the amount of pending rewards applied to the To account
	// as part of this transaction.
	// Required: false
	ToRewards uint64 `json:"torewards,omitempty"`

	// CloseRewards is the amount of pending rewards applied to the CloseRemainderTo
	// account as part of this transaction.
	// Required: false
	CloseRewards uint64 `json:"closerewards,omitempty"`
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

// Supply represents the current supply of MicroAlgos in the system
// swagger:model Supply
type Supply struct {

	// OnlineMoney
	// Required: true
	OnlineMoney uint64 `json:"onlineMoney"`

	// Round
	// Required: true
	Round uint64 `json:"round"`

	// TotalMoney
	// Required: true
	TotalMoney uint64 `json:"totalMoney"`
}

// Transaction contains all fields common to all transactions and serves as an envelope to all transactions
// type
// swagger:model Transaction
type Transaction struct {

	// ConfirmedRound indicates the block number this transaction appeared in
	ConfirmedRound uint64 `json:"round,omitempty"`

	// PoolError indicates the transaction was evicted from this node's transaction
	// pool (if non-empty).  A non-empty PoolError does not guarantee that the
	// transaction will never be committed; other nodes may not have evicted the
	// transaction and may attempt to commit it in the future.
	PoolError string `json:"poolerror,omitempty"`

	// Fee is the transaction fee
	// Required: true
	Fee uint64 `json:"fee"`

	// FirstRound indicates the first valid round for this transaction
	// Required: true
	FirstRound uint64 `json:"first-round"`

	// From is the sender's address
	// Required: true
	From string `json:"from"`

	// LastRound indicates the last valid round for this transaction
	// Required: true
	LastRound uint64 `json:"last-round"`

	// Note is a free form data
	Note []uint8 `json:"noteb64"`

	// TxID is the transaction ID
	// Required: true
	TxID string `json:"tx"`

	// payment
	Payment *PaymentTransactionType `json:"payment,omitempty"`

	// FromRewards is the amount of pending rewards applied to the From
	// account as part of this transaction.
	// Required: false
	FromRewards uint64 `json:"fromrewards,omitempty"`

	// type
	// Required: true
	Type TxType `json:"type"`

	// Genesis ID
	//
	// required: true
	GenesisID string `json:"genesisID"`

	// Genesis hash
	//
	// required: true
	GenesisHash []byte `json:"genesishashb64"`
}

// TransactionFee contains the suggested fee
// swagger:model TransactionFee
type TransactionFee struct {

	// Fee is transaction fee
	// Required: true
	Fee uint64 `json:"fee"`
}

// TransactionParams contains the parameters that help a client construct
// a new transaction.
// swagger:model TransactionParams
type TransactionParams struct {
	// Fee is the suggested transaction fee
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
}

// TransactionID Description
// swagger:model TransactionID
type TransactionID struct {

	// TxId is the string encoding of the transaction hash
	// Required: true
	TxID string `json:"txId"`
}

// TransactionList contains a list of transactions
// swagger:model TransactionList
type TransactionList struct {

	// TransactionList is a list of rewards
	// Required: true
	Transactions []Transaction `json:"transactions"`
}

// TxType is the type of the transaction written to the ledger
// swagger:model TxType
type TxType string

// Version contains the current algod version.
//
// Note that we annotate this as a model so that legacy clients
// can directly import a swagger generated Version model.
// swagger:model Version
type Version struct {

	// genesis ID
	// Required: true
	GenesisID *string `json:"genesis_id"`

	// genesis hash
	// Required: true
	GenesisHash []byte `json:"genesis_hash_b64"`

	// versions
	// Required: true
	Versions []string `json:"versions"`
}
