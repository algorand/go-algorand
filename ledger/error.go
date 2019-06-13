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

package ledger

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// TransactionInLedgerError is returned when a transaction cannot be added because it has already been done
type TransactionInLedgerError struct {
	Txid transactions.Txid
}

// Error satisfies builtin interface `error`
func (tile TransactionInLedgerError) Error() string {
	return fmt.Sprintf("transaction already in ledger: %v", tile.Txid)
}

// BlockInLedgerError is returned when a block cannot be added because it has already been done
type BlockInLedgerError struct {
	LastRound basics.Round
	NextRound basics.Round
}

// Error satisfies builtin interface `error`
func (bile BlockInLedgerError) Error() string {
	return fmt.Sprintf("block number already in ledger: block %d < next Round %d", bile.LastRound, bile.NextRound)
}

// ProtocolError is used to indicate that an unsupported protocol has been detected.
type ProtocolError protocol.ConsensusVersion

// Error satisfies builtin interface `error`
func (err ProtocolError) Error() string {
	return fmt.Sprintf("protocol not supported: %s", err)
}

// ErrNoEntry is used to indicate that a block is not present in the ledger.
type ErrNoEntry struct {
	Round     basics.Round
	Latest    basics.Round
	Committed basics.Round
}

// Error satisfies builtin interface `error`
func (err ErrNoEntry) Error() string {
	return fmt.Sprintf("ledger does not have entry %d (latest %d, committed %d)", err.Round, err.Latest, err.Committed)
}
