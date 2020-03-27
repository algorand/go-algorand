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
	"strings"

	//"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
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
	log    logging.Logger
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
func MakeCatchpointCatchupAccessor(ledger *Ledger, log logging.Logger) *CatchpointCatchupAccessor {
	return &CatchpointCatchupAccessor{
		ledger: ledger,
		log:    log,
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
func (c *CatchpointCatchupAccessor) ProgressStagingBalances(ctx context.Context, sectionName string, bytes []byte) (err error) {
	if sectionName == "content.msgpack" {
		return c.processStagingContent(ctx, bytes)
	}
	if strings.HasPrefix(sectionName, "balances.") && strings.HasSuffix(sectionName, ".msgpack") {
		return c.processStagingBalances(ctx, bytes)
	}
	// we want to allow undefined sections to support backward compatibility.
	c.log.Warnf("CatchpointCatchupAccessor::ProgressStagingBalances encountered unexpected section name '%s' of length %d, which would be ignored", sectionName, len(bytes))
	return nil
}

// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessor) processStagingContent(ctx context.Context, bytes []byte) (err error) {
	var fileHeader catchpointFileHeader
	err = protocol.DecodeReflect(bytes, &fileHeader)
	if err != nil {
		return err
	}
	if fileHeader.Version != initialVersion {
		return fmt.Errorf("unable to process catchpoint - version %d is not supported", fileHeader.Version)
	}

	// the following fields are now going to be ignored. We should add these to the database and validate these
	// later on:
	// TotalAccounts, TotalAccounts, Catchpoint, BlockHeaderDigest, BalancesRound
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupBlockRound", uint64(fileHeader.BlocksRound))
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupLabel': %v", err)
		}
		err = accountsPutTotals(tx, fileHeader.Totals, true)
		return
	})
	return err
}

// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessor) processStagingBalances(ctx context.Context, bytes []byte) (err error) {
	var balances catchpointFileBalancesChunk
	err = protocol.DecodeReflect(bytes, &balances)
	if err != nil {
		return err
	}

	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		err = writeCatchpointStagingBalances(ctx, tx, balances)
		if err != nil {
			return
		}
		return
	})

	return nil
}
