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

package data

import (
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
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

	// a two-item moving window cache for the total number of online circulating coins
	lastRoundCirculation atomic.Value
	// a two-item moving window cache for the round seed
	lastRoundSeed atomic.Value
}

// roundCirculationPair used to hold a pair of matching round number and the amount of online money
type roundCirculationPair struct {
	round       basics.Round
	onlineMoney basics.MicroAlgos
}

// roundCirculation is the cache for the circulating coins
type roundCirculation struct {
	// elements holds several round-onlineMoney pairs
	elements [2]roundCirculationPair
}

// roundSeedPair is the cache for a single seed at a given round
type roundSeedPair struct {
	round basics.Round
	seed  committee.Seed
}

// roundSeed is the cache for the seed
type roundSeed struct {
	// elements holds several round-seed pairs
	elements [2]roundSeedPair
}

// LoadLedger creates a Ledger object to represent the ledger with the
// specified database file prefix, initializing it if necessary.
func LoadLedger(
	log logging.Logger, dbFilenamePrefix string, memory bool,
	genesisProto protocol.ConsensusVersion, genesisBal bookkeeping.GenesisBalances, genesisID string, genesisHash crypto.Digest,
	blockListeners []ledger.BlockListener, cfg config.Local,
) (*Ledger, error) {
	if genesisBal.Balances == nil {
		genesisBal.Balances = make(map[basics.Address]basics.AccountData)
	}
	genBlock, err := bookkeeping.MakeGenesisBlock(genesisProto, genesisBal, genesisID, genesisHash)
	if err != nil {
		return nil, err
	}

	params := config.Consensus[genesisProto]
	if params.ForceNonParticipatingFeeSink {
		sinkAddr := genesisBal.FeeSink
		sinkData := genesisBal.Balances[sinkAddr]
		sinkData.Status = basics.NotParticipating
		genesisBal.Balances[sinkAddr] = sinkData
	}

	l := &Ledger{
		log: log,
	}
	genesisInitState := ledgercore.InitState{
		Block:       genBlock,
		Accounts:    genesisBal.Balances,
		GenesisHash: genesisHash,
	}
	l.log.Debugf("Initializing Ledger(%s)", dbFilenamePrefix)

	ll, err := ledger.OpenLedger(log, dbFilenamePrefix, memory, genesisInitState, cfg)
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

	var res []transactions.SignedTxnWithAD
	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return nil, err
	}
	for _, tx := range payset {
		if tx.Txn.MatchAddress(id, spec) {
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

	payset, err := blk.DecodePaysetFlat()
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

// Circulation implements agreement.Ledger.Circulation.
func (l *Ledger) Circulation(r basics.Round) (basics.MicroAlgos, error) {
	circulation, cached := l.lastRoundCirculation.Load().(roundCirculation)
	if cached && r != basics.Round(0) {
		for _, element := range circulation.elements {
			if element.round == r {
				return element.onlineMoney, nil
			}
		}
	}

	totals, err := l.OnlineTotals(r)
	if err != nil {
		return basics.MicroAlgos{}, err
	}

	if !cached || r > circulation.elements[1].round {
		l.lastRoundCirculation.Store(
			roundCirculation{
				elements: [2]roundCirculationPair{
					circulation.elements[1],
					{
						round:       r,
						onlineMoney: totals},
				},
			})
	}

	return totals, nil
}

// Seed gives the VRF seed that was agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.Seed
func (l *Ledger) Seed(r basics.Round) (committee.Seed, error) {
	seed, cached := l.lastRoundSeed.Load().(roundSeed)
	if cached && r != basics.Round(0) {
		for _, roundSeed := range seed.elements {
			if roundSeed.round == r {
				return roundSeed.seed, nil
			}
		}
	}

	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return committee.Seed{}, err
	}

	if !cached || r > seed.elements[1].round {
		l.lastRoundSeed.Store(
			roundSeed{
				elements: [2]roundSeedPair{
					seed.elements[1],
					{
						round: r,
						seed:  blockhdr.Seed,
					},
				},
			})
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
// returning an error if the consensus version could not be figured using
// either the block header for the given round, or the latest block header.
// Implements agreement.Ledger.ConsensusVersion
func (l *Ledger) ConsensusVersion(r basics.Round) (protocol.ConsensusVersion, error) {
	blockhdr, err := l.BlockHdr(r)
	if err == nil {
		return blockhdr.UpgradeState.CurrentProtocol, nil
	}
	// try to see if we can figure out what the version would be.
	latestCommittedRound, latestRound := l.LatestCommitted()
	// if the request round was for an older round, then just say the we don't know.
	if r < latestRound {
		return "", err
	}
	// the request was for a future round. See if we have any known plans for the next round.
	latestBlockhdr, err := l.BlockHdr(latestRound)
	// if we have the lastest block header, look inside and try to figure out if we can deduce the
	// protocol version for the given round.
	if err == nil {
		// check to see if we have a protocol upgrade.
		if latestBlockhdr.NextProtocolSwitchOn == 0 {
			// no protocol upgrade taking place, we have *at least* UpgradeVoteRounds before the protocol version would get changed.
			// it's safe to ignore the error case here since we know that we couldn't reached to this "known" round
			// without having the binary supporting this protocol version.
			currentConsensusParams, _ := config.Consensus[latestBlockhdr.CurrentProtocol]
			// we're using <= here since there is no current upgrade on this round, and if there will be one on the subsequent round
			// it would still be correct until (latestBlockhdr.Round + currentConsensusParams.UpgradeVoteRounds)
			if r <= latestBlockhdr.Round+basics.Round(currentConsensusParams.UpgradeVoteRounds) {
				return latestBlockhdr.CurrentProtocol, nil
			}
			// otherwise, we can't really tell.
			return "", ledgercore.ErrNoEntry{Round: r, Latest: latestRound, Committed: latestCommittedRound}
		}
		// in this case, we do have a protocol upgrade taking place.
		if r < latestBlockhdr.NextProtocolSwitchOn {
			// if we're in the voting duration or uprade waiting period, then the protocol version is the current version.
			return latestBlockhdr.CurrentProtocol, nil
		}
		// if the requested round aligns with the protocol version switch version and we've passed the voting period, then we know that on the switching round
		// we will be using the next protocol.
		if r == latestBlockhdr.NextProtocolSwitchOn && latestBlockhdr.Round >= latestBlockhdr.NextProtocolVoteBefore {
			return latestBlockhdr.NextProtocol, nil
		}
		err = ledgercore.ErrNoEntry{Round: r, Latest: latestRound, Committed: latestCommittedRound}
	}
	// otherwise, we can't really tell what the protocol version would be at round r.
	return "", err
}

// EnsureValidatedBlock ensures that the block, and associated certificate c, are
// written to the ledger, or that some other block for the same round is
// written to the ledger.
func (l *Ledger) EnsureValidatedBlock(vb *ledgercore.ValidatedBlock, c agreement.Certificate) {
	round := vb.Block().Round()

	for l.LastRound() < round {
		err := l.AddValidatedBlock(*vb, c)
		if err == nil {
			break
		}

		logfn := l.log.Errorf

		switch err.(type) {
		case ledgercore.BlockInLedgerError:
			// If the block is already in the ledger (catchup and agreement might be competing),
			// reporting this as a debug message is sufficient.
			logfn = l.log.Debugf
			// Otherwise, the error is because the block is in the future. Error is logged.
		}
		logfn("data.EnsureValidatedBlock: could not write block %d to the ledger: %v", round, err)
	}
}

// EnsureBlock ensures that the block, and associated certificate c, are
// written to the ledger, or that some other block for the same round is
// written to the ledger.
// This function can be called concurrently.
func (l *Ledger) EnsureBlock(block *bookkeeping.Block, c agreement.Certificate) {
	round := block.Round()
	protocolErrorLogged := false

	for l.LastRound() < round {
		err := l.AddBlock(*block, c)
		if err == nil {
			break
		}

		switch err.(type) {
		case protocol.Error:
			if !protocolErrorLogged {
				l.log.Errorf("data.EnsureBlock: unrecoverable protocol error detected at block %d: %v", round, err)
				protocolErrorLogged = true
			}
		case ledgercore.BlockInLedgerError:
			// The block is already in the ledger. Catchup and agreement could be competing
			// It is sufficient to report this as a Debug message
			l.log.Debugf("data.EnsureBlock: could not write block %d to the ledger: %v", round, err)
			return
		default:
			l.log.Errorf("data.EnsureBlock: could not write block %d to the ledger: %v", round, err)
		}

		// If there was an error add a short delay before the next attempt.
		time.Sleep(100 * time.Millisecond)
	}
}
