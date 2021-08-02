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
	"time"

	"github.com/algorand/go-algorand/agreement"
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
		l:  base.l,
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
		return v.vb.state.totals()
	}
	return v.l.Totals(r)
}

// A speculativeBlock is a block that we have validated, but have not agreed
// upon (no continuous chain of certificates).  There may be a certificate
// associated with a speculativeBlock, if we get a certificate for a speculative
// block out-of-order with its parent.  In this case, we hang on to the certificate
// until all of the parents are committed themselves.
type speculativeBlock struct {
	lfe  *validatedBlockAsLFE
	cert *agreement.Certificate
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
	blocks map[bookkeeping.BlockHash]speculativeBlock

	// l is the committed ledger.
	l *Ledger

	// dbs is l.trackerDB()
	dbs db.Pair
}

// speculativeBlocksSchema describes the on-disk state format for storing
// speculative blocks.  We make the round number explicit so that we can
// more easily sort and delete by round number.
var speculativeBlockSchema = []string{
	`CREATE TABLE IF NOT EXISTS speculative (
		rnd integer,
		blkhash blob,
		blkdata blob,
		certdata blob,
		PRIMARY KEY (rnd, blkhash))`,
}

// addSpeculativeBlock records a new speculative block.
func (st *speculationTracker) addSpeculativeBlock(vblk ValidatedBlock, cert *agreement.Certificate) error {
	err := st.addSpeculativeBlockInMem(vblk, cert)
	if err != nil {
		return err
	}

	var certbuf []byte
	if cert != nil {
		certbuf = protocol.Encode(cert)
	}

	blkhash := vblk.blk.Hash()
	err = st.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO speculative (rnd, blkhash, blkdata, certdata) VALUES (?, ?, ?, ?)",
			vblk.blk.Round(), blkhash[:], protocol.Encode(&vblk.blk), certbuf)
		return err
	})

	return nil
}

// addSpeculativeBlockInMem updates the in-memory state with a new speculative
// block, but does not store the block on-disk.
func (st *speculationTracker) addSpeculativeBlockInMem(vblk ValidatedBlock, cert *agreement.Certificate) error {
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
	st.blocks[h] = speculativeBlock{
		lfe:  lfe,
		cert: cert,
	}
	return nil
}

type blkcert struct {
	blk  bookkeeping.Block
	cert *agreement.Certificate
}

func (st *speculationTracker) loadFromDisk(l *Ledger) error {
	st.l = l
	st.dbs = st.l.trackerDB()
	st.blocks = make(map[bookkeeping.BlockHash]speculativeBlock)

	var blocks []blkcert

	err := st.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		for _, tableCreate := range speculativeBlockSchema {
			_, err := tx.Exec(tableCreate)
			if err != nil {
				return fmt.Errorf("speculationTracker could not create: %v", err)
			}
		}

		rows, err := tx.Query("SELECT blkdata, certdata FROM speculative ORDER BY rnd ASC")
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var blkbuf []byte
			var certbuf []byte
			err = rows.Scan(&blkbuf, &certbuf)
			if err != nil {
				return err
			}

			var entry blkcert
			err = protocol.Decode(blkbuf, &entry.blk)
			if err != nil {
				return err
			}

			if len(certbuf) > 0 {
				entry.cert = new(agreement.Certificate)
				err = protocol.Decode(certbuf, entry.cert)
				if err != nil {
					return err
				}
			}

			blocks = append(blocks, entry)
		}

		return nil
	})
	if err != nil {
		return err
	}

	for _, entry := range blocks {
		blk := &entry.blk
		var parentLedger ledgerForEvaluator
		if blk.Round() == l.Latest()+1 {
			parentLedger = l
		} else {
			parentHash := blk.Branch
			parent, ok := st.blocks[parentHash]
			if !ok {
				l.trackerLog().Warnf("speculationTracker.loadFromDisk: cannot find parent %v for block %v round %d, latest %d", parentHash, blk.Hash(), blk.Round(), l.Latest())
				continue
			}
			parentLedger = parent.lfe
		}

		state, err := l.trackerEvalVerified(*blk, parentLedger)
		if err != nil {
			l.trackerLog().Warnf("speculationTracker.loadFromDisk: block %d round %d: %v", blk.Hash(), blk.Round(), err)
			continue
		}

		vblk := ValidatedBlock{
			blk:   *blk,
			state: state,
		}
		err = st.addSpeculativeBlockInMem(vblk, entry.cert)
		if err != nil {
			l.trackerLog().Warnf("speculationTracker.loadFromDisk: block %d round %d: addSpeculativeBlockInMem: %v", blk.Hash(), blk.Round(), err)
		}
	}

	return nil
}

func (st *speculationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	for h, specblk := range st.blocks {
		if specblk.lfe.vb.blk.Round() < blk.Round() {
			// Older blocks hanging around for whatever reason.
			// Shouldn't happen, but clean them up just in case.
			delete(st.blocks, h)
		}

		if specblk.lfe.vb.blk.Round() == blk.Round() {
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

		if specblk.lfe.vb.blk.Round() == blk.Round()+1 &&
			specblk.lfe.vb.blk.Branch == blk.Hash() {

			// If this is a child of the now-committed block,
			// update its parent ledger pointer to avoid chains
			// of validatedBlockAsLFE's.
			specblk.lfe.resetParent(st.l)

			// If this child has a certificate associated with it,
			// add the block to the ledger.  This will in turn cause
			// the ledger to call our newBlock() again, which will
			// commit any subsequent blocks that already have certs.
			if specblk.cert != nil {
				st.l.EnsureValidatedBlock(specblk.lfe.vb, *specblk.cert)
			}
		}
	}

	err := st.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE FROM speculative WHERE rnd<=?", blk.Round())
		return err
	})
	if err != nil {
		st.l.trackerLog().Warnf("speculationTracker.newBlock: cannot delete blocks up to %d: %v", blk.Round(), err)
	}
}

func (st *speculationTracker) invalidateChildren(branch bookkeeping.BlockHash) {
	for h, specblk := range st.blocks {
		if specblk.lfe.vb.blk.Branch == branch {
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
	*Ledger
}

// MakeSpeculativeLedger constructs a SpeculativeLedger around a Ledger.
func MakeSpeculativeLedger(l *Ledger) *SpeculativeLedger {
	return &SpeculativeLedger{
		Ledger: l,
	}
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

// LFE returns a ledgerForEvaluator for round r from the speculative ledger.
func (sl *SpeculativeLedger) LFE(r basics.Round, leaf bookkeeping.BlockHash) (ledgerForEvaluator, error) {
	sl.trackerMu.Lock()
	defer sl.trackerMu.Unlock()

	entry, ok := sl.speculate.blocks[leaf]
	if ok {
		return entry.lfe, nil
	}

	if r <= sl.Latest() {
		return sl.Ledger, nil
	}

	return nil, leafNotFound{h: leaf}
}

// blockHdr returns the block header for round r from the speculative ledger.
func (sl *SpeculativeLedger) BlockHdr(r basics.Round, leaf bookkeeping.BlockHash) (bookkeeping.BlockHeader, error) {
	lfe, err := sl.LFE(r, leaf)
	if err != nil {
		return bookkeeping.BlockHeader{}, err
	}

	return lfe.BlockHdr(r)
}

// NextRound returns the next round for which no block has been committed.
func (sl *SpeculativeLedger) NextRound() basics.Round {
	return sl.Latest() + 1
}

// Wait returns a channel that closes once a given round is stored
// durably.  If the block was added speculatively, Wait indicates
// when the block is durably stored as a speculative block.  If the
// block was added non-speculatively, Wait indicates when the block
// is durably stored as a non-speculative block.
//
// Wait properly supports waiting for a round r that has already been
// added (but perhaps not durably stored yet) for both speculative and
// non-speculative blocks.
//
// Wait supports waiting for a round r that has not been added yet, but
// only for non-speculative blocks.  It is not well-defined which speculative
// block for round r, to be added later, we might want to wait for.
func (sl *SpeculativeLedger) Wait(r basics.Round, leaf bookkeeping.BlockHash) chan struct{} {
	// Check for a pending non-speculative block.  This might exist
	// even if we already have a speculative block too.
	if r <= sl.Latest() {
		return sl.Ledger.Wait(r)
	}

	// Check if we have a speculative block for this round.  Speculative
	// blocks are currently written to durable storage synchronously, so
	// no waiting is needed.
	sl.trackerMu.Lock()
	entry, ok := sl.speculate.blocks[leaf]
	sl.trackerMu.Unlock()
	if ok && r <= entry.lfe.vb.blk.Round() {
		closed := make(chan struct{})
		close(closed)
		return closed
	}

	// No speculative block present, and not pending in the blockQ.
	// Wait for the block to be inserted by someone else (e.g., catchup).
	return sl.Ledger.Wait(r)
}

// Seed returns the VRF seed that in a given round's block header.
func (sl *SpeculativeLedger) Seed(r basics.Round, leaf bookkeeping.BlockHash) (committee.Seed, error) {
	blockhdr, err := sl.BlockHdr(r, leaf)
	if err != nil {
		return committee.Seed{}, err
	}
	return blockhdr.Seed, nil
}

// Lookup returns the AccountData associated with some Address at the
// conclusion of a given round.
func (sl *SpeculativeLedger) Lookup(r basics.Round, leaf bookkeeping.BlockHash, addr basics.Address) (basics.AccountData, error) {
	lfe, err := sl.LFE(r, leaf)
	if err != nil {
		return basics.AccountData{}, err
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
	lfe, err := sl.LFE(r, leaf)
	if err != nil {
		return basics.MicroAlgos{}, err
	}

	totals, err := lfe.Totals(r)
	if err != nil {
		return basics.MicroAlgos{}, err
	}

	return totals.Online.Money, nil
}

// LookupDigest returns the Digest of the block that was agreed on in a given round.
func (sl *SpeculativeLedger) LookupDigest(r basics.Round, leaf bookkeeping.BlockHash) (crypto.Digest, error) {
	blockhdr, err := sl.BlockHdr(r, leaf)
	if err != nil {
		return crypto.Digest{}, err
	}
	return crypto.Digest(blockhdr.Hash()), nil
}

// ConsensusParams returns the consensus parameters for a given round.
func (sl *SpeculativeLedger) ConsensusParams(r basics.Round, leaf bookkeeping.BlockHash) (config.ConsensusParams, error) {
	blockhdr, err := sl.BlockHdr(r, leaf)
	if err != nil {
		return config.ConsensusParams{}, err
	}
	return config.Consensus[blockhdr.CurrentProtocol], nil
}

// ConsensusVersion returns the consensus version for a given round.
func (sl *SpeculativeLedger) ConsensusVersion(r basics.Round, leaf bookkeeping.BlockHash) (protocol.ConsensusVersion, error) {
	blockhdr, err := sl.BlockHdr(r, leaf)
	if err != nil {
		return "", err
	}
	return blockhdr.CurrentProtocol, nil
}

// AddSpeculativeBlock records a new speculative block.
func (sl *SpeculativeLedger) AddSpeculativeBlock(vblk ValidatedBlock) error {
	sl.trackerMu.Lock()
	defer sl.trackerMu.Unlock()
	return sl.speculate.addSpeculativeBlock(vblk, nil)
}

// AddBlock adds a certificate together with a block to the ledger.
func (sl *SpeculativeLedger) AddBlock(blk bookkeeping.Block, cert agreement.Certificate) error {
	vb, err := sl.Validate(context.Background(), blk.Branch, blk)
	if err != nil {
		return err
	}

	return sl.AddValidatedBlock(*vb, cert)
}

// AddValidatedBlock adds a certificate together with a block to the ledger.
func (sl *SpeculativeLedger) AddValidatedBlock(vb ValidatedBlock, cert agreement.Certificate) error {
	sl.trackerMu.Lock()

	// If this block is for the next round expected by the ledger,
	// add it directly to the underlying ledger.  That avoids writing
	// the cert to disk twice.  The tracker lock does not guard against
	// concurrent insertion of blocks, but the latest round returned
	// by the ledger is monotonically increasing, so if it increments
	// concurrently with us, the block insertion should error out anyway.
	if vb.blk.Round() == sl.Latest()+1 {
		sl.trackerMu.Unlock()
		return sl.Ledger.AddValidatedBlock(vb, cert)
	}

	// This is a speculative block.  We are holding the trackerMu, which
	// will serialize us with respect to calls to newBlock().  We rely
	// on that so that newBlock() will insert this certificate into the
	// ledger, if/when this block stops being speculative.
	defer sl.trackerMu.Unlock()

	// This block might be not even in our set of known speculative blocks
	// yet, so add it there if need be.  addSpeculativeBlock() takes a cert,
	// so nothing left for us to do if we invoke it.
	entry, ok := sl.speculate.blocks[vb.blk.Hash()]
	if !ok {
		return sl.speculate.addSpeculativeBlock(vb, &cert)
	}

	entry.cert = &cert
	blkhash := entry.lfe.vb.blk.Hash()
	return sl.speculate.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE speculative SET certdata=? WHERE rnd=? AND blkhash=?",
			protocol.Encode(&cert), entry.lfe.vb.blk.Round(), blkhash[:])
		return err
	})
}

// Validate validates whether a block is valid, on a particular leaf branch.
func (sl *SpeculativeLedger) Validate(ctx context.Context, leaf bookkeeping.BlockHash, blk bookkeeping.Block) (*ValidatedBlock, error) {
	state, err := sl.eval(ctx, leaf, blk, true, nil)
	if err != nil {
		return nil, err
	}

	return &ValidatedBlock{
		blk:   blk,
		state: state,
	}, nil
}

// eval evaluates a block on a particular leaf branch.
func (sl *SpeculativeLedger) eval(ctx context.Context, leaf bookkeeping.BlockHash, blk bookkeeping.Block, validate bool, executionPool execpool.BacklogPool) (*roundCowState, error) {
	lfe, err := sl.LFE(blk.Round().SubSaturate(1), leaf)
	if err != nil {
		return nil, err
	}

	return eval(ctx, lfe, blk, validate, sl.verifiedTxnCache, executionPool)
}

// StartEvaluator starts a block evaluator with a particular block header.
// The block header's Branch value determines which speculative branch is used.
// This is intended to be used by the transaction pool assembly code.
func (sl *SpeculativeLedger) StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint int) (*BlockEvaluator, error) {
	lfe, err := sl.LFE(hdr.Round.SubSaturate(1), hdr.Branch)
	if err != nil {
		return nil, err
	}

	return startEvaluator(lfe, hdr, paysetHint, true, true)
}

// EnsureBlock ensures that the block, and associated certificate c, are
// written to the speculative ledger, or that some other block for the
// same round is written to the ledger.
// This function can be called concurrently.
func (sl *SpeculativeLedger) EnsureBlock(block *bookkeeping.Block, c agreement.Certificate) {
	round := block.Round()
	protocolErrorLogged := false

	// As a fallback, bail out if the base (non-speculative) ledger has a
	// block for the same round number.
	for sl.Latest() < round {
		err := sl.AddBlock(*block, c)
		if err == nil {
			break
		}

		switch err.(type) {
		case protocol.Error:
			if !protocolErrorLogged {
				logging.Base().Errorf("unrecoverable protocol error detected at block %d: %v", round, err)
				protocolErrorLogged = true
			}
		case ledgercore.BlockInLedgerError:
			logging.Base().Debugf("could not write block %d to the ledger: %v", round, err)
			return // this error implies that l.Latest() >= round
		default:
			logging.Base().Errorf("could not write block %d to the speculative ledger: %v", round, err)
		}

		// If there was an error add a short delay before the next attempt.
		time.Sleep(100 * time.Millisecond)
	}
}

// EnsureValidatedBlock ensures that the block, and associated certificate c, are
// written to the speculative ledger, or that some other block for the same round is
// written to the ledger.
func (sl *SpeculativeLedger) EnsureValidatedBlock(vb *ValidatedBlock, c agreement.Certificate) {
	round := vb.Block().Round()

	// As a fallback, bail out if the base (non-speculative) ledger has a
	// block for the same round number.
	for sl.Latest() < round {
		err := sl.AddValidatedBlock(*vb, c)
		if err == nil {
			break
		}

		logfn := logging.Base().Errorf

		switch err.(type) {
		case ledgercore.BlockInLedgerError:
			logfn = logging.Base().Debugf
		}

		logfn("could not write block %d to the speculative ledger: %v", round, err)
	}
}
