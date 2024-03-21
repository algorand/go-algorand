// Copyright (C) 2019-2024 Algorand, Inc.
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

package stateproof

import (
	"context"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

// TransactionSender is an interface that captures the node's ability
// to broadcast a new transaction.
type TransactionSender interface {
	BroadcastInternalSignedTxGroup([]transactions.SignedTxn) error
}

// Ledger captures the aspects of the ledger that are used by this package.
type Ledger interface {
	Latest() basics.Round
	Wait(basics.Round) chan struct{}
	GenesisHash() crypto.Digest
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	VotersForStateProof(basics.Round) (*ledgercore.VotersForRound, error)
	RegisterVotersCommitListener(listener ledgercore.VotersCommitListener)
	UnregisterVotersCommitListener()
}

// Network captures the aspects of the gossip network protocol that are
// used by this package.
type Network interface {
	Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except network.Peer) error
	RegisterHandlers([]network.TaggedMessageHandler)
}

// Accounts captures the aspects of the AccountManager that are used by
// this package.
type Accounts interface {
	StateProofKeys(basics.Round) []account.StateProofSecretsForRound
	DeleteStateProofKey(id account.ParticipationID, round basics.Round) error
}

// BlockHeaderFetcher captures the aspects of the Ledger that is used to fetch block headers
type BlockHeaderFetcher interface {
	BlockHdr(round basics.Round) (bookkeeping.BlockHeader, error)
}
