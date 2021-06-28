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

package data

import (
	"fmt"
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

func makeGenesisBlock(proto protocol.ConsensusVersion, genesisBal GenesisBalances, genesisID string, genesisHash crypto.Digest) (bookkeeping.Block, error) {
	params, ok := config.Consensus[proto]
	if !ok {
		return bookkeeping.Block{}, fmt.Errorf("unsupported protocol %s", proto)
	}

	poolAddr := basics.Address(genesisBal.rewardsPool)
	incentivePoolBalanceAtGenesis := genesisBal.balances[poolAddr].MicroAlgos

	genesisRewardsState := bookkeeping.RewardsState{
		FeeSink:                   genesisBal.feeSink,
		RewardsPool:               genesisBal.rewardsPool,
		RewardsLevel:              0,
		RewardsResidue:            0,
		RewardsRecalculationRound: basics.Round(params.RewardsRateRefreshInterval),
	}

	if params.InitialRewardsRateCalculation {
		genesisRewardsState.RewardsRate = basics.SubSaturate(incentivePoolBalanceAtGenesis.Raw, params.MinBalance) / uint64(params.RewardsRateRefreshInterval)
	} else {
		genesisRewardsState.RewardsRate = incentivePoolBalanceAtGenesis.Raw / uint64(params.RewardsRateRefreshInterval)
	}

	genesisProtoState := bookkeeping.UpgradeState{
		CurrentProtocol: proto,
	}

	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round:        0,
			Branch:       bookkeeping.BlockHash{},
			Seed:         committee.Seed(genesisHash),
			TxnRoot:      transactions.Payset{}.CommitGenesis(),
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

	return blk, nil
}

// LoadLedger creates a Ledger object to represent the ledger with the
// specified database file prefix, initializing it if necessary.
func LoadLedger(
	log logging.Logger, dbFilenamePrefix string, memory bool,
	genesisProto protocol.ConsensusVersion, genesisBal GenesisBalances, genesisID string, genesisHash crypto.Digest,
	blockListeners []ledger.BlockListener, cfg config.Local,
) (*Ledger, error) {
	if genesisBal.balances == nil {
		genesisBal.balances = make(map[basics.Address]basics.AccountData)
	}
	genBlock, err := makeGenesisBlock(genesisProto, genesisBal, genesisID, genesisHash)
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
	genesisInitState := ledger.InitState{
		Block:       genBlock,
		Accounts:    genesisBal.balances,
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

	totals, err := l.Totals(r)
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
						onlineMoney: totals.Online.Money},
				},
			})
	}

	return totals.Online.Money, nil
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
		case ledgercore.BlockInLedgerError:
			logfn = logging.Base().Debugf
		}

		logfn("could not write block %d to the ledger: %v", round, err)
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
				logging.Base().Errorf("unrecoverable protocol error detected at block %d: %v", round, err)
				protocolErrorLogged = true
			}
		case ledgercore.BlockInLedgerError:
			logging.Base().Debugf("could not write block %d to the ledger: %v", round, err)
			return // this error implies that l.LastRound() >= round
		default:
			logging.Base().Errorf("could not write block %d to the ledger: %v", round, err)
		}

		// If there was an error add a short delay before the next attempt.
		time.Sleep(100 * time.Millisecond)
	}
}
