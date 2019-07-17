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

package data

import (
	"container/heap"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
)

// The Ledger object in this (data) package provides a wrapper around the
// Ledger from the ledger package.  The reason for this is compatibility
// with the existing callers of the previous ledger API, without increasing
// the complexity of the ledger.Ledger code.  This Ledger object also
// implements various wrappers that return subsets of data exposed by
// ledger.Ledger, or return it in different forms, or return it for the
// latest round (as opposed to arbitrary rounds).
type Ledger struct {
	*ledger.Ledger

	log logging.Logger
}

func makeGenesisBlocks(proto protocol.ConsensusVersion, genesisBal GenesisBalances, genesisID string, genesisHash crypto.Digest) ([]bookkeeping.Block, error) {
	params, ok := config.Consensus[proto]
	if !ok {
		return nil, fmt.Errorf("unsupported protocol %s", proto)
	}

	poolAddr := basics.Address(genesisBal.rewardsPool)
	incentivePoolBalanceAtGenesis := genesisBal.balances[poolAddr].MicroAlgos

	genesisRewardsState := bookkeeping.RewardsState{
		FeeSink:                   genesisBal.feeSink,
		RewardsPool:               genesisBal.rewardsPool,
		RewardsLevel:              0,
		RewardsRate:               incentivePoolBalanceAtGenesis.Raw / uint64(params.RewardsRateRefreshInterval),
		RewardsResidue:            0,
		RewardsRecalculationRound: basics.Round(params.RewardsRateRefreshInterval),
	}

	genesisProtoState := bookkeeping.UpgradeState{
		CurrentProtocol: proto,
	}

	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round:        0,
			Branch:       bookkeeping.BlockHash{},
			Seed:         committee.Seed(genesisHash),
			TxnRoot:      transactions.Payset{}.Commit(params.PaysetCommitFlat),
			TimeStamp:    genesisBal.timestamp,
			GenesisID:    genesisID,
			RewardsState: genesisRewardsState,
			UpgradeState: genesisProtoState,
			UpgradeVote:  bookkeeping.UpgradeVote{},
		},
	}

	if params.SupportGenesisHash {
		blk.BlockHeader.GenesisHash = genesisHash
	}

	blocks := []bookkeeping.Block{blk}
	return blocks, nil
}

// LoadLedger creates a Ledger object to represent the ledger with the
// specified database file prefix, initializing it if necessary.
func LoadLedger(log logging.Logger, dbFilenamePrefix string, memory bool, genesisProto protocol.ConsensusVersion, genesisBal GenesisBalances, genesisID string, genesisHash crypto.Digest, blockListeners []ledger.BlockListener) (*Ledger, error) {
	if genesisBal.balances == nil {
		genesisBal.balances = make(map[basics.Address]basics.AccountData)
	}
	genBlocks, err := makeGenesisBlocks(genesisProto, genesisBal, genesisID, genesisHash)
	if err != nil {
		return nil, err
	}

	params := config.Consensus[genesisProto]
	if params.ForceNonParticipatingFeeSink {
		sinkAddr := genesisBal.feeSink
		sinkData := genesisBal.balances[sinkAddr]
		sinkData.Status = basics.NotParticipating
		genesisBal.balances[sinkAddr] = sinkData
	}

	l := &Ledger{
		log: log,
	}
	l.log.Debugf("Initializing Ledger(%s)", dbFilenamePrefix)

	ll, err := ledger.OpenLedger(log, dbFilenamePrefix, memory, genBlocks, genesisBal.balances, genesisHash)
	if err != nil {
		return nil, err
	}

	l.Ledger = ll
	l.RegisterBlockListeners(blockListeners)
	return l, nil
}

// AddressTxns returns the list of transactions to/from a given address in specific round
func (l *Ledger) AddressTxns(id basics.Address, r basics.Round) ([]transactions.SignedTxnWithAD, error) {
	blk, err := l.Block(r)
	if err != nil {
		return nil, err
	}
	spec := transactions.SpecialAddresses{
		FeeSink:     blk.FeeSink,
		RewardsPool: blk.RewardsPool,
	}
	proto := config.Consensus[blk.CurrentProtocol]

	var res []transactions.SignedTxnWithAD
	payset, err := blk.DecodePaysetWithAD()
	if err != nil {
		return nil, err
	}
	for _, tx := range payset {
		if tx.Txn.MatchAddress(id, spec, proto) {
			res = append(res, tx)
		}
	}
	return res, nil
}

// LookupTxid returns the transaction with a given ID in a specific round
func (l *Ledger) LookupTxid(txid transactions.Txid, r basics.Round) (stxn transactions.SignedTxnWithAD, found bool, err error) {
	var blk bookkeeping.Block
	blk, err = l.Block(r)
	if err != nil {
		return transactions.SignedTxnWithAD{}, false, err
	}

	payset, err := blk.DecodePaysetWithAD()
	if err != nil {
		return transactions.SignedTxnWithAD{}, false, err
	}
	for _, tx := range payset {
		if tx.ID() == txid {
			return tx, true, nil
		}
	}
	return transactions.SignedTxnWithAD{}, false, nil
}

// LastRound returns the local latest round of the network i.e. the *last* written block
func (l *Ledger) LastRound() basics.Round {
	return l.Latest()
}

// NextRound returns the *next* block to write i.e. latest() + 1
// Implements agreement.Ledger.NextRound
func (l *Ledger) NextRound() basics.Round {
	return l.LastRound() + 1
}

// BalanceRecord implements Ledger.BalanceRecord.
func (l *Ledger) BalanceRecord(r basics.Round, addr basics.Address) (basics.BalanceRecord, error) {
	data, err := l.Lookup(r, addr)
	if err != nil {
		return basics.BalanceRecord{}, err
	}

	return basics.BalanceRecord{
		Addr:        addr,
		AccountData: data,
	}, nil
}

// BalanceAndStatus returns Balance and DelegationStatus as one call
func (l *Ledger) BalanceAndStatus(addr basics.Address) (money basics.MicroAlgos, rewards basics.MicroAlgos, moneyWithoutPendingRewards basics.MicroAlgos, status basics.Status, latest basics.Round, err error) {
	latest = l.Latest()
	data, err := l.Lookup(latest, addr)
	if err != nil {
		return
	}

	totals, err := l.Totals(latest)
	if err != nil {
		return
	}

	hdr, err := l.BlockHdr(latest)
	if err != nil {
		return
	}
	proto, ok := config.Consensus[hdr.CurrentProtocol]
	if !ok {
		err = ledger.ProtocolError(hdr.CurrentProtocol)
	}

	money, rewards = data.Money(proto, totals.RewardsLevel)
	status = data.Status

	dataWithoutRewards, err := l.LookupWithoutRewards(latest, addr)
	if err != nil {
		return
	}
	moneyWithoutPendingRewards = dataWithoutRewards.MicroAlgos

	return
}

// Circulation implements agreement.Ledger.Circulation.
func (l *Ledger) Circulation(r basics.Round) (basics.MicroAlgos, error) {
	totals, err := l.Totals(r)
	if err != nil {
		return basics.MicroAlgos{}, err
	}

	return totals.Online.Money, nil
}

// Seed gives the VRF seed that was agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.Seed
func (l *Ledger) Seed(r basics.Round) (committee.Seed, error) {
	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return committee.Seed{}, err
	}
	return blockhdr.Seed, nil
}

// LookupDigest gives the block hash that was agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.LookupDigest
func (l *Ledger) LookupDigest(r basics.Round) (crypto.Digest, error) {
	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return crypto.Digest{}, err
	}
	return crypto.Digest(blockhdr.Hash()), nil
}

// ConsensusParams gives the consensus parameters agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.ConsensusParams
func (l *Ledger) ConsensusParams(r basics.Round) (config.ConsensusParams, error) {
	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return config.ConsensusParams{}, err
	}
	return config.Consensus[blockhdr.UpgradeState.CurrentProtocol], nil
}

// ConsensusVersion gives the consensus version agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.ConsensusVersion
func (l *Ledger) ConsensusVersion(r basics.Round) (protocol.ConsensusVersion, error) {
	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return "", err
	}
	return blockhdr.UpgradeState.CurrentProtocol, nil
}

// EnsureValidatedBlock ensures that the block, and associated certificate c, are
// written to the ledger, or that some other block for the same round is
// written to the ledger.
func (l *Ledger) EnsureValidatedBlock(vb *ledger.ValidatedBlock, c agreement.Certificate) {
	round := vb.Block().Round()

	for l.LastRound() < round {
		err := l.AddValidatedBlock(*vb, c)
		if err == nil {
			break
		}

		logfn := logging.Base().Errorf

		switch err.(type) {
		case ledger.BlockInLedgerError:
			logfn = logging.Base().Debugf
		}

		logfn("could not write block %d to the ledger: %v", round, err)
	}
}

// EnsureBlock ensures that the block, and associated certificate c, are
// written to the ledger, or that some other block for the same round is
// written to the ledger.
func (l *Ledger) EnsureBlock(block *bookkeeping.Block, c agreement.Certificate) {
	round := block.Round()
	protocolErrorLogged := false

	for l.LastRound() < round {
		err := l.AddBlock(*block, c)
		if err == nil {
			break
		}

		switch err.(type) {
		case ledger.ProtocolError:
			if !protocolErrorLogged {
				logging.Base().Errorf("unrecoverable protocol error detected at block %d: %v", round, err)
				protocolErrorLogged = true
			}
		case ledger.BlockInLedgerError:
			logging.Base().Debugf("could not write block %d to the ledger: %v", round, err)
			return // this error implies that l.LastRound() >= round
		default:
			logging.Base().Errorf("could not write block %d to the ledger: %v", round, err)
		}

		// If there was an error add a short delay before the next attempt.
		time.Sleep(100 * time.Millisecond)
	}
}

// AssemblePayset adds transactions to a BlockEvaluator.
func (*Ledger) AssemblePayset(pool *pools.TransactionPool, eval *ledger.BlockEvaluator, deadline time.Time) (stats telemetryspec.AssembleBlockStats) {
	pending := pool.PendingUnsorted()
	pheap := txnHeap{make([]*transactions.SignedTxn, 0, len(pending))}
	for i := range pending {
		pheap.Add(&pending[i])
	}
	stats.StartCount = len(pending)
	stats.StopReason = telemetryspec.AssembleBlockEmpty
	first := true
	totalFees := uint64(0)

	for true {
		txn := pheap.Next()
		if txn == nil {
			break
		}
		if time.Now().After(deadline) {
			stats.StopReason = telemetryspec.AssembleBlockTimeout
			break
		}

		err := eval.Transaction(*txn, nil)
		if err == ledger.ErrNoSpace {
			stats.StopReason = telemetryspec.AssembleBlockFull
			break
		}
		if err != nil {
			msg := fmt.Sprintf("Cannot add pending transaction to block: %v", err)

			logAt := logging.Base().Warn

			// GOAL2-255: Don't warn for common case of txn already being in ledger
			switch err.(type) {
			case ledger.TransactionInLedgerError:
				logAt = logging.Base().Debug
				stats.CommittedCount++
			case transactions.MinFeeError:
				logAt = logging.Base().Info
				stats.InvalidCount++
			default:
				// logAt = Warn
				stats.InvalidCount++
			}

			logAt(msg)
		} else {
			fee := txn.Txn.Fee.Raw
			encodedLen := txn.GetEncodedLength()
			priority := uint64(txn.PtrPriority())

			stats.IncludedCount++
			totalFees += fee

			if first {
				first = false
				stats.MinFee = fee
				stats.MaxFee = fee
				stats.MinLength = encodedLen
				stats.MaxLength = encodedLen
				stats.MinPriority = priority
				stats.MaxPriority = priority
			} else {
				if fee < stats.MinFee {
					stats.MinFee = fee
				} else if fee > stats.MaxFee {
					stats.MaxFee = fee
				}
				if encodedLen < stats.MinLength {
					stats.MinLength = encodedLen
				} else if encodedLen > stats.MaxLength {
					stats.MaxLength = encodedLen
				}
				if priority < stats.MinPriority {
					stats.MinPriority = priority
				} else if priority > stats.MaxPriority {
					stats.MaxPriority = priority
				}
			}
			stats.TotalLength += uint64(encodedLen)
		}

		if stats.IncludedCount != 0 {
			stats.AverageFee = totalFees / uint64(stats.IncludedCount)
		}
	}
	return
}

type txnHeap struct {
	they []*transactions.SignedTxn
}

func (th *txnHeap) Add(stxn *transactions.SignedTxn) {
	heap.Push(th, stxn)
}

func (th *txnHeap) Next() *transactions.SignedTxn {
	if len(th.they) == 0 {
		return nil
	}
	out := heap.Pop(th)
	return out.(*transactions.SignedTxn)
}

// Push implements heap.Interface
func (th *txnHeap) Push(x interface{}) {
	th.they = append(th.they, x.(*transactions.SignedTxn))
}

// Pop implements heap.Interface
func (th *txnHeap) Pop() interface{} {
	lasti := len(th.they) - 1
	out := th.they[lasti]
	th.they = th.they[:lasti]
	return out
}

// Len is the number of elements in the collection.
// heap.Interface sort.Interface
func (th *txnHeap) Len() int {
	return len(th.they)
}

// Less reports whether the element with
// index i should sort before the element with index j.
// heap.Interface sort.Interface
func (th *txnHeap) Less(i, j int) bool {
	// "container/heap" natural sort is least first.
	// Reverse that to return highest Priority first by checking for (j < i)
	return th.they[j].PtrPriority().LessThan(th.they[i].PtrPriority())
}

// Swap swaps the elements with indexes i and j.
// heap.Interface sort.Interface
func (th *txnHeap) Swap(i, j int) {
	t := th.they[i]
	th.they[i] = th.they[j]
	th.they[j] = t
}
