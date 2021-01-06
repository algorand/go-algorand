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

package mocks

import (
	"context"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
)

// MockCatchpointCatchupAccessor is a dummy CatchpointCatchupAccessor implementation which doesn't do anything.
type MockCatchpointCatchupAccessor struct{}

// GetState returns the current state of the catchpoint catchup
func (m *MockCatchpointCatchupAccessor) GetState(ctx context.Context) (state ledger.CatchpointCatchupState, err error) {
	return ledger.CatchpointCatchupStateInactive, nil
}

// SetState set the state of the catchpoint catchup
func (m *MockCatchpointCatchupAccessor) SetState(ctx context.Context, state ledger.CatchpointCatchupState) (err error) {
	return nil
}

// GetLabel returns the current catchpoint catchup label
func (m *MockCatchpointCatchupAccessor) GetLabel(ctx context.Context) (label string, err error) {
	return "", nil
}

// SetLabel set the catchpoint catchup label
func (m *MockCatchpointCatchupAccessor) SetLabel(ctx context.Context, label string) (err error) {
	return nil
}

// ResetStagingBalances resets the current staging balances, preparing for a new set of balances to be added
func (m *MockCatchpointCatchupAccessor) ResetStagingBalances(ctx context.Context, newCatchup bool) (err error) {
	return nil
}

// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
func (m *MockCatchpointCatchupAccessor) ProgressStagingBalances(ctx context.Context, sectionName string, bytes []byte, progress *ledger.CatchpointCatchupAccessorProgress) (err error) {
	return nil
}

// BuildMerkleTrie inserts the account hashes into the merkle trie
func (m *MockCatchpointCatchupAccessor) BuildMerkleTrie(ctx context.Context, progressUpdates func(uint64)) (err error) {
	return nil
}

// GetCatchupBlockRound returns the latest block round matching the current catchpoint
func (m *MockCatchpointCatchupAccessor) GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error) {
	return basics.Round(0), nil
}

// VerifyCatchpoint verifies that the catchpoint is valid by reconstructing the label.
func (m *MockCatchpointCatchupAccessor) VerifyCatchpoint(ctx context.Context, blk *bookkeeping.Block) (err error) {
	return nil
}

// StoreBalancesRound calculates the balances round based on the first block and the associated consensus parametets, and
// store that to the database
func (m *MockCatchpointCatchupAccessor) StoreBalancesRound(ctx context.Context, blk *bookkeeping.Block) (err error) {
	return nil
}

// StoreFirstBlock stores a single block to the blocks database.
func (m *MockCatchpointCatchupAccessor) StoreFirstBlock(ctx context.Context, blk *bookkeeping.Block) (err error) {
	return nil
}

// StoreBlock stores a single block to the blocks database.
func (m *MockCatchpointCatchupAccessor) StoreBlock(ctx context.Context, blk *bookkeeping.Block) (err error) {
	return nil
}

// FinishBlocks concludes the catchup of the blocks database.
func (m *MockCatchpointCatchupAccessor) FinishBlocks(ctx context.Context, applyChanges bool) (err error) {
	return nil
}

// EnsureFirstBlock ensure that we have a single block in the staging block table, and returns that block
func (m *MockCatchpointCatchupAccessor) EnsureFirstBlock(ctx context.Context) (blk bookkeeping.Block, err error) {
	return bookkeeping.Block{}, nil
}

// CompleteCatchup completes the catchpoint catchup process by switching the databases tables around
// and reloading the ledger.
func (m *MockCatchpointCatchupAccessor) CompleteCatchup(ctx context.Context) (err error) {
	return nil
}
