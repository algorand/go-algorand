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

package ledger

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/execpool"
)

// validatedBlockAsLFE presents a ledgerForEvaluator interface on top of
// a ValidatedBlock.  This makes it possible to construct a BlockEvaluator
// on top, which in turn allows speculatively constructing a subsequent
// block, before the ValidatedBlock is committed to the ledger.
//
// This is what the state looks like:
//
// previousLFE <--------- roundCowBase
//      ^           l         ^
//      |                     | lookupParent
//      |                     |
//      |               roundCowState
//      |                     ^
//      |                     | state
//      |                     |
//	|		ValidatedBlock -------> Block
//      |                     ^          blk
//      |                     | vb
//      |     l               |
//      \---------- validatedBlockAsLFE
//
// where previousLFE might be the full ledger, or might be another
// validatedBlockAsLFE.
type validatedBlockAsLFE struct {
	// l points to the underlying ledger; it might be another instance
	// of validatedBlockAsLFE if we are speculating on a chain of many
	// blocks.
	l ledgerForEvaluator

	// vb points to the ValidatedBlock that logically extends the
	// state of the ledger.
	vb *ValidatedBlock
}

// makeValidatedBlockAsLFE constructs a new validatedBlockAsLFE from a
// ValidatedBlock.
func makeValidatedBlockAsLFE(vb *ValidatedBlock) (*validatedBlockAsLFE, error) {
	if vb.state.commitParent != nil {
		return nil, fmt.Errorf("makeValidatedBlockAsLFE(): vb not committed")
	}

	base, ok := vb.state.lookupParent.(*roundCowBase)
	if !ok {
		return nil, fmt.Errorf("makeValidatedBlockAsLFE(): missing roundCowBase")
	}

	return &validatedBlockAsLFE{
		l: base.l,
		vb: vb,
	}, nil
}

// resetParent() changes the parent ledger of this validated block to l.
// This is used when the parent block is committed, so that we can garbage
// collect the parent's validatedBlockAsLFE and instead start using the
// committed ledger.
func (v *validatedBlockAsLFE) resetParent(l ledgerForEvaluator) error {
	base, ok := v.vb.state.lookupParent.(*roundCowBase)
	if !ok {
		return fmt.Errorf("validatedBlockAsLFE: lookupParent no longer roundCowBase")
	}

	v.l = l
	base.l = l
	return nil
}

// BlockHdr implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	if r == v.vb.blk.Round() {
		return v.vb.blk.BlockHeader, nil
	}

	return v.l.BlockHdr(r)
}

// CheckDup implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) CheckDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl TxLease) error {
	if current == v.vb.blk.Round() {
		return v.vb.state.checkDup(firstValid, lastValid, txid, txl.Txlease)
	}

	return v.l.CheckDup(currentProto, current, firstValid, lastValid, txid, txl)
}

// CompactCertVoters implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) CompactCertVoters(r basics.Round) (*VotersForRound, error) {
	if r >= v.vb.blk.Round() {
		// We do not support computing the compact cert voters for rounds
		// that have not been committed to the ledger yet.  This should not
		// be a problem as long as the agreement pipeline depth does not
		// exceed CompactCertVotersLookback.
		err := fmt.Errorf("validatedBlockAsLFE.CompactCertVoters(%d): validated block is for round %d, voters not available", r, v.vb.blk.Round())
		logging.Base().Warn(err.Error())
		return nil, err
	}

	return v.l.CompactCertVoters(r)
}

// GenesisHash implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) GenesisHash() crypto.Digest {
	return v.l.GenesisHash()
}

// GetCreatorForRound implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) GetCreatorForRound(r basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	if r == v.vb.blk.Round() {
		return v.vb.state.getCreator(cidx, ctype)
	}

	return v.l.GetCreatorForRound(r, cidx, ctype)
}

// LookupWithoutRewards implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) LookupWithoutRewards(r basics.Round, a basics.Address) (basics.AccountData, basics.Round, error) {
	if r == v.vb.blk.Round() {
		data, err := v.vb.state.lookup(a)
		return data, r, err
	}

	return v.l.LookupWithoutRewards(r, a)
}

// Totals implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) Totals(r basics.Round) (ledgercore.AccountTotals, error) {
	if r == v.vb.blk.Round() {
		return v.vb.state.modtotals, nil
	}
	return v.l.Totals(r)
}

func xxStartEvaluatorVB(vb *ValidatedBlock, hdr bookkeeping.BlockHeader, paysetHint int) (*BlockEvaluator, error) {
	lfe, err := makeValidatedBlockAsLFE(vb)
	if err != nil {
		return nil, err
	}

	return startEvaluator(lfe, hdr, paysetHint, true, true)
}

// The speculationTracker tracks speculative blocks that have been proposed
// over the network but that have not yet been agreed upon (no certificate).
//
// The speculationTracker uses the tracker interface to monitor the real
// ledger for committed blocks.  The ledger's tracker rwmutex protects
// concurrent operations on the speculationTracker.
type speculationTracker struct {
	// blocks contains the set of blocks that we have received in a
	// proposal but for whose round we have not yet reached consensus.
	blocks map[bookkeeping.BlockHash]*validatedBlockAsLFE

	// l is the committed ledger.
	l ledgerForTracker

	// dbs is l.trackerDB()
	dbs db.Pair
}

// speculativeBlocksSchema describes the on-disk state format for storing
// speculative blocks.  We make the round number explicit so that we can
// more easily sort and delete by round number.
var speculativeBlockSchema = []string{
	`CREATE TABLE IF NOT EXISTS speculative (
		rnd integer,
		blkdata blob)`,
}

// addSpeculativeBlock records a new speculative block.
func (st *speculationTracker) addSpeculativeBlock(vblk ValidatedBlock) error {
	err := st.addSpeculativeBlockInMem(vblk)
	if err != nil {
		return err
	}

	err = st.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO speculative (rnd, blkdata) VALUES (?, ?)",
			vblk.blk.Round(), protocol.Encode(&vblk.blk))
		return err
	})

	return nil
}

// addSpeculativeBlockInMem updates the in-memory state with a new speculative
// block, but does not store the block on-disk.
func (st *speculationTracker) addSpeculativeBlockInMem(vblk ValidatedBlock) error {
	// The parent of this block must be committed or present in the
	// speculation tracker.
	latest := st.l.Latest()
	if vblk.blk.Round() > latest+1 {
		prevhash := vblk.blk.Branch
		_, ok := st.blocks[prevhash]
		if !ok {
			return fmt.Errorf("addSpeculativeBlockInMem(%d): latest is %d, missing parent %s", vblk.blk.Round(), latest, prevhash)
		}
	}

	lfe, err := makeValidatedBlockAsLFE(&vblk)
	if err != nil {
		return err
	}

	h := vblk.blk.Hash()
	st.blocks[h] = lfe
	return nil
}

func (st *speculationTracker) loadFromDisk(l ledgerForTracker) error {
	st.l = l
	st.dbs = st.l.trackerDB()
	st.blocks = make(map[bookkeeping.BlockHash]*validatedBlockAsLFE)

	var blocks []bookkeeping.Block

	err := st.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		for _, tableCreate := range speculativeBlockSchema {
			_, err := tx.Exec(tableCreate)
			if err != nil {
				return fmt.Errorf("speculationTracker could not create: %v", err)
			}
		}

		rows, err := tx.Query("SELECT blkdata FROM speculative ORDER BY rnd ASC")
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var buf []byte
			err = rows.Scan(&buf)
			if err != nil {
				return err
			}

			var blk bookkeeping.Block
			err = protocol.Decode(buf, &blk)
			if err != nil {
				return err
			}

			blocks = append(blocks, blk)
		}

		return nil
	})
	if err != nil {
		return err
	}

	for _, blk := range blocks {
		var parentLedger ledgerForEvaluator
		if blk.Round() == l.Latest() + 1 {
			// XXX
			// parentLedger = l
			parentLedger = nil
		} else {
			parentHash := blk.Branch
			parent, ok := st.blocks[parentHash]
			if !ok {
				l.trackerLog().Warnf("speculationTracker.loadFromDisk: cannot find parent %v for block %v round %d, latest %d", parentHash, blk.Hash(), blk.Round(), l.Latest())
				continue
			}
			parentLedger = parent
		}

		state, err := l.trackerEvalVerified(blk, parentLedger)
		if err != nil {
			l.trackerLog().Warnf("speculationTracker.loadFromDisk: block %d round %d: %v", blk.Hash(), blk.Round(), err)
			continue
		}

		vblk := ValidatedBlock{
			blk: blk,
			state: state,
		}
		err = st.addSpeculativeBlockInMem(vblk)
		if err != nil {
			l.trackerLog().Warnf("speculationTracker.loadFromDisk: block %d round %d: addSpeculativeBlockInMem: %v", blk.Hash(), blk.Round(), err)
		}
	}

	return nil
}

func (st *speculationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	// First, check if we have an existing speculative entry for this block.
	// If so, we need to remember its parent ledger so that we can update its
	// children to have the same parent ledger.
	var parentLedger ledgerForEvaluator
	specblk, ok := st.blocks[blk.Hash()]
	if ok {
		parentLedger = specblk.l
	}

	for h, specblk := range st.blocks {
		if specblk.vb.blk.Round() < blk.Round() {
			// Older blocks hanging around for whatever reason.
			// Shouldn't happen, but clean them up just in case.
			delete(st.blocks, h)
		}

		if specblk.vb.blk.Round() == blk.Round() {
			// Block for the same round.  Clear it out.
			delete(st.blocks, h)

			if h == blk.Hash() {
				// Same block; we speculated correctly.
			} else {
				// Different block for the same round.
				// Now we know this is an incorrect speculation;
				// clear out its children too.
				st.invalidateChildren(h)
			}
		}

		if specblk.vb.blk.Round() == blk.Round() + 1 {
			// If this is a child of the now-committed block,
			// update its parent ledger pointer to avoid chains
			// of validatedBlockAsLFE's.
			if specblk.vb.blk.Branch == blk.Hash() && parentLedger != nil {
				specblk.resetParent(parentLedger)
			}
		}
	}
}

func (st *speculationTracker) invalidateChildren(branch bookkeeping.BlockHash) {
	for h, specblk := range st.blocks {
		if specblk.vb.blk.Branch == branch {
			delete(st.blocks, h)
			st.invalidateChildren(h)
		}
	}
}

func (st *speculationTracker) committedUpTo(r basics.Round) basics.Round {
	return r
}

func (st *speculationTracker) close() {
}

// SpeculativeLedger is an alternative view of the Ledger that exports methods
// to access speculative blocks.  This allows having methods with the same
// name but different arguments, between Ledger and SpeculativeLedger.
type SpeculativeLedger struct {
	l *Ledger
}

// leafNotFound is an error indicating that the leaf hash was not present
// in the speculative ledger.
type leafNotFound struct {
	h bookkeeping.BlockHash
}

// Error implements the error interface.
func (lnf leafNotFound) Error() string {
	return fmt.Sprintf("SpeculativeLedger.blockHdr: leaf %v not found", lnf.h)
}

// blockHdr returns the block header for round r from the speculative
// ledger.
func (sl *SpeculativeLedger) blockHdr(r basics.Round, leaf bookkeeping.BlockHash) (bookkeeping.BlockHeader, error){
	sl.l.trackerMu.Lock()
	defer sl.l.trackerMu.Unlock()

	if leaf != (bookkeeping.BlockHash{}) {
		lfe, ok := sl.l.speculate.blocks[leaf]
		if !ok {
			return bookkeeping.BlockHeader{}, leafNotFound{h: leaf}
		}

		return lfe.BlockHdr(r)
	}

	return sl.l.BlockHdr(r)
}

// NextRound returns the next round for which no block has been committed.
func (sl *SpeculativeLedger) NextRound() basics.Round {
	return sl.l.Latest() + 1
}

// Wait returns a channel that closes once a given round is stored
// durably in the non-speculative ledger, or that is already closed
// if the block is already present in the speculative ledger.  The
// channel will not close when the block is later added to the
// speculative ledger.
func (sl *SpeculativeLedger) Wait(r basics.Round, leaf bookkeeping.BlockHash) chan struct{} {
	sl.l.trackerMu.Lock()
	lfe, ok := sl.l.speculate.blocks[leaf]
	sl.l.trackerMu.Unlock()
	if ok && r <= lfe.vb.blk.Round() {
		closed := make(chan struct{})
		close(closed)
		return closed
	}

	return sl.l.Wait(r)
}

// Seed returns the VRF seed that in a given round's block header.
func (sl *SpeculativeLedger) Seed(r basics.Round, leaf bookkeeping.BlockHash) (committee.Seed, error) {
	blockhdr, err := sl.blockHdr(r, leaf)
	if err != nil {
		return committee.Seed{}, err
	}
	return blockhdr.Seed, nil
}

// Lookup returns the AccountData associated with some Address at the
// conclusion of a given round.
func (sl *SpeculativeLedger) Lookup(r basics.Round, leaf bookkeeping.BlockHash, addr basics.Address) (basics.AccountData, error) {
	if leaf == (bookkeeping.BlockHash{}) {
		return sl.l.Lookup(r, addr)
	}

	sl.l.trackerMu.Lock()
	lfe, ok := sl.l.speculate.blocks[leaf]
	sl.l.trackerMu.Unlock()
	if !ok {
		return basics.AccountData{}, leafNotFound{h: leaf}
	}

	data, _, err := lfe.LookupWithoutRewards(r, addr)
	if err != nil {
		return basics.AccountData{}, err
	}

	blockhdr, err := lfe.BlockHdr(r)
	if err != nil {
		return basics.AccountData{}, err
	}

	rewardsProto := config.Consensus[blockhdr.CurrentProtocol]
	rewardsLevel := blockhdr.RewardsLevel
	return data.WithUpdatedRewards(rewardsProto, rewardsLevel), nil
}

// Circulation returns the total amount of money in online accounts at the
// conclusion of a given round.
func (sl *SpeculativeLedger) Circulation(r basics.Round, leaf bookkeeping.BlockHash) (basics.MicroAlgos, error) {
	if leaf == (bookkeeping.BlockHash{}) {
		totals, err := sl.l.Totals(r)
		if err != nil {
			return basics.MicroAlgos{}, err
		}
		return totals.Online.Money, nil
	}

	sl.l.trackerMu.Lock()
	lfe, ok := sl.l.speculate.blocks[leaf]
	sl.l.trackerMu.Unlock()
	if !ok {
		return basics.MicroAlgos{}, leafNotFound{h: leaf}
	}

	totals, err := lfe.Totals(r)
	if err != nil {
		return basics.MicroAlgos{}, err
	}

	return totals.Online.Money, nil
}

// LookupDigest returns the Digest of the block that was agreed on in a given round.
func (sl *SpeculativeLedger) LookupDigest(r basics.Round, leaf bookkeeping.BlockHash) (crypto.Digest, error) {
	blockhdr, err := sl.blockHdr(r, leaf)
	if err != nil {
		return crypto.Digest{}, err
	}
	return crypto.Digest(blockhdr.Hash()), nil
}

// ConsensusParams returns the consensus parameters for a given round.
func (sl *SpeculativeLedger) ConsensusParams(r basics.Round, leaf bookkeeping.BlockHash) (config.ConsensusParams, error) {
	blockhdr, err := sl.blockHdr(r, leaf)
	if err != nil {
		return config.ConsensusParams{}, err
	}
	return config.Consensus[blockhdr.CurrentProtocol], nil
}

// ConsensusVersion returns the consensus version for a given round.
func (sl *SpeculativeLedger) ConsensusVersion(r basics.Round, leaf bookkeeping.BlockHash) (protocol.ConsensusVersion, error) {
	blockhdr, err := sl.blockHdr(r, leaf)
	if err != nil {
		return "", err
	}
	return blockhdr.CurrentProtocol, nil
}

// AddSpeculativeBlock records a new speculative block.
func (sl *SpeculativeLedger) AddSpeculativeBlock(vblk ValidatedBlock) error {
	sl.l.trackerMu.Lock()
	defer sl.l.trackerMu.Unlock()
	return sl.l.speculate.addSpeculativeBlock(vblk)
}

// Validate validates whether a block is valid, on a particular leaf branch.
func (sl *SpeculativeLedger) Validate(ctx context.Context, leaf bookkeeping.BlockHash, blk bookkeeping.Block) (*ValidatedBlock, error) {
	state, err := sl.eval(ctx, leaf, blk, true, nil)
	if err != nil {
		return nil, err
	}

	return &ValidatedBlock{
		blk: blk,
		state: state,
	}, nil
}

// eval evaluates a block on a particular leaf branch.
func (sl *SpeculativeLedger) eval(ctx context.Context, leaf bookkeeping.BlockHash, blk bookkeeping.Block, validate bool, executionPool execpool.BacklogPool) (*roundCowState, error) {
	var lfe ledgerForEvaluator
	if leaf == (bookkeeping.BlockHash{}) {
		lfe = sl.l
	} else {
		var ok bool
		sl.l.trackerMu.Lock()
		lfe, ok = sl.l.speculate.blocks[leaf]
		sl.l.trackerMu.Unlock()
		if !ok {
			return nil, leafNotFound{h: leaf}
		}
	}

	return eval(ctx, lfe, blk, validate, sl.l.verifiedTxnCache, executionPool)
}
