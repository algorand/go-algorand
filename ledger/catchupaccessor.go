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

package ledger

import (
	"context"
	"database/sql"
	"fmt"
	/*"archive/tar"
	  "compress/gzip"
	  "context"
	  "database/sql"
	  "fmt"
	  "hash"
	  "io"
	  "os"
	  "path/filepath"

	  "github.com/algorand/go-codec/codec"

	  "github.com/algorand/go-algorand/data/basics"
	  "github.com/algorand/go-algorand/data/bookkeeping"
	  "github.com/algorand/go-algorand/protocol"
	  "github.com/algorand/go-algorand/util/db"*/)

// CatchpointCatchupAccessor is an accessor wrapping the database storage for the catchpoint catchup functionality.
type CatchpointCatchupAccessor struct {
	ledger *Ledger
}

// CatchpointCatchupState is the state of the current catchpoint catchup process
type CatchpointCatchupState int

const (
	// CatchpointCatchupStateInactive is the common state for the catchpoint catchup - not active.
	CatchpointCatchupStateInactive = iota
	// CatchpointCatchupStateLedgerDownload indicates that we're downloading the ledger
	CatchpointCatchupStateLedgerDownload
	// CatchpointCatchupStateLastestBlockDownload indicates that we're download the latest block
	CatchpointCatchupStateLastestBlockDownload
	// CatchpointCatchupStateBlocksDownload indicates that we're downloading the blocks prior to the latest one ( total of MaxBalLookback blocks )
	CatchpointCatchupStateBlocksDownload
	// CatchpointCatchupStateSwitch indicates that we're switching to use the downloaded ledger/blocks content
	CatchpointCatchupStateSwitch

	// catchpointCatchupStateLast is the last entries in the CatchpointCatchupState enumeration.
	catchpointCatchupStateLast = CatchpointCatchupStateSwitch
)

// MakeCatchpointCatchupAccessor creates a CatchpointCatchupAccessor given a ledger
func MakeCatchpointCatchupAccessor(ledger *Ledger) *CatchpointCatchupAccessor {
	return &CatchpointCatchupAccessor{
		ledger: ledger,
	}
}

// GetState returns the current state of the catchpoint catchup
func (c *CatchpointCatchupAccessor) GetState(ctx context.Context) (state CatchpointCatchupState, err error) {
	rdb := c.ledger.trackerDB().rdb
	err = rdb.Atomic(func(tx *sql.Tx) (err error) {
		var istate uint64
		istate, _, err = readCatchpointStateUint64(ctx, tx, "catchpointCatchupState")
		if err != nil {
			return fmt.Errorf("unable to read catchpoint catchup state 'catchpointCatchupState': %v", err)
		}
		state = CatchpointCatchupState(istate)
		return
	})
	return
}

// SetState set the state of the catchpoint catchup
func (c *CatchpointCatchupAccessor) SetState(ctx context.Context, state CatchpointCatchupState) (err error) {
	if state < CatchpointCatchupStateInactive || state > catchpointCatchupStateLast {
		return fmt.Errorf("invalid catchpoint catchup state provided : %d", state)
	}
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupState", uint64(state))
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupState': %v", err)
		}
		return
	})
	return
}

// GetLabel returns the current catchpoint catchup label
func (c *CatchpointCatchupAccessor) GetLabel(ctx context.Context) (label string, err error) {
	rdb := c.ledger.trackerDB().rdb
	err = rdb.Atomic(func(tx *sql.Tx) (err error) {
		label, _, err = readCatchpointStateString(ctx, tx, "catchpointCatchupLabel")
		if err != nil {
			return fmt.Errorf("unable to read catchpoint catchup state 'catchpointCatchupLabel': %v", err)
		}
		return
	})
	return
}

// SetLabel set the catchpoint catchup label
func (c *CatchpointCatchupAccessor) SetLabel(ctx context.Context, label string) (err error) {
	wdb := c.ledger.trackerDB().wdb
	// verify it's parsable :
	_, _, err = ParseCatchpointLabel(label)
	if err != nil {
		return
	}
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateString(ctx, tx, "catchpointCatchupLabel", label)
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupLabel': %v", err)
		}
		return
	})
	return
}

// ResetStagingBalances resets the current staging balances, preparing for a new set of balances to be added
func (c *CatchpointCatchupAccessor) ResetStagingBalances(ctx context.Context) (err error) {
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		err = resetCatchpointStagingBalances(ctx, tx)
		if err != nil {
			return fmt.Errorf("unable to reset catchpoint catchup balances : %v", err)
		}
		return
	})
	return
}

// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessor) ProgressStagingBalances(sectionName string, bytes []byte) (err error) {
	return nil
}
