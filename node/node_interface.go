// Copyright (C) 2019-2022 Algorand, Inc.
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

package node

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/node/indexer"
)

// BaseNodeInterface defines the set of methods required for the algod server
type BaseNodeInterface interface {
	ListeningAddress() (string, bool)
	Start()
	Stop()
	Config() config.Local
	GenesisHash() crypto.Digest
	GenesisID() string
	LedgerForAPI() ledger.LedgerForAPI
	Status() (s StatusReport, err error)
}

// DataNodeInterface defines the set of methods required for algod APIs tagged as `data`
type DataNodeInterface interface {
	NonParticipatingNodeInterface
	SetSyncRound(rnd uint64) error
	GetSyncRound() (uint64, error)
	UnsetSyncRound() error
}

// NonParticipatingNodeInterface defines the set of methods required for algod APIs tagged as `nonparticipating`
type NonParticipatingNodeInterface interface {
	BaseNodeInterface
	StartCatchup(catchpoint string) error
	AbortCatchup(catchpoint string) error
	IsArchival() bool
	Indexer() (*indexer.Indexer, error)
	GetTransactionByID(txid transactions.Txid, rnd basics.Round) (TxnWithStatus, error)
	GetTransaction(addr basics.Address, txID transactions.Txid, minRound basics.Round, maxRound basics.Round) (TxnWithStatus, bool)
	ListTxns(addr basics.Address, minRound basics.Round, maxRound basics.Round) ([]TxnWithStatus, error)
}

// ParticipatingNodeInterface represents node fns used by the handlers for APIs tagged as `participating.
type ParticipatingNodeInterface interface {
	NonParticipatingNodeInterface
	BroadcastSignedTxGroup(txgroup []transactions.SignedTxn) error
	GetPendingTransaction(txID transactions.Txid) (res TxnWithStatus, found bool)
	GetPendingTxnsFromPool() ([]transactions.SignedTxn, error)
	SuggestedFee() basics.MicroAlgos
	InstallParticipationKey(partKeyBinary []byte) (account.ParticipationID, error)
	ListParticipationKeys() ([]account.ParticipationRecord, error)
	GetParticipationKey(account.ParticipationID) (account.ParticipationRecord, error)
	RemoveParticipationKey(account.ParticipationID) error
	AppendParticipationKeys(id account.ParticipationID, keys account.StateProofKeys) error
}
