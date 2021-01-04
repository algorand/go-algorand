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

package logspec

import (
	"encoding/json"
	"errors"
)

// LedgerType is an enum identifying a specific type of LedgerEvent
// TODO Maybe this should be called LedgerEventType, since these are not actually types of ledgers
//go:generate stringer -type=LedgerType
type LedgerType int

const (
	// WroteBlock is emitted whenever a block is written to the ledger
	WroteBlock LedgerType = iota

	numLedgerTypes // keep this last
)

// LedgerEvent represents data corresponding to an event occurring related to the ledger
type LedgerEvent struct {
	Event

	Type LedgerType

	// Round of the block just written
	Round uint64

	// Hash is the block hash of the block just written
	Hash string

	// Number of transactions in the block just written
	TxnCount int
}

func ledgerTypeFromString(s string) (LedgerType, bool) {
	for i := 0; i < int(numLedgerTypes); i++ {
		t := LedgerType(i)
		if t.String() == s {
			return t, true
		}
	}
	return 0, false
}

// UnmarshalJSON initializes the LedgerType from a JSON string contained in a byte buffer.
// An error is returned if a valid LedgerType can't be parsed from the buffer.
func (t *LedgerType) UnmarshalJSON(b []byte) error {
	var raw string
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	typeConst, ok := ledgerTypeFromString(raw)
	if !ok {
		return errors.New("invalid LedgerType field")
	}

	*t = typeConst
	return nil
}
