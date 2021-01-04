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

package datatest

import (
	"context"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
)

// This file is a copy of node/impls.go.
type entryValidatorImpl struct {
	l *data.Ledger
}

type validatedBlock struct {
	blk *bookkeeping.Block
}

// Validate implements BlockValidator.Validate.
func (i entryValidatorImpl) Validate(ctx context.Context, e bookkeeping.Block) (agreement.ValidatedBlock, error) {
	ve := validatedBlock{
		blk: &e,
	}

	return ve, nil
}

type entryFactoryImpl struct {
	l *data.Ledger
}

// AssembleBlock implements Ledger.AssembleBlock.
func (i entryFactoryImpl) AssembleBlock(round basics.Round, deadline time.Time) (agreement.ValidatedBlock, error) {
	prev, err := i.l.BlockHdr(round - 1)
	if err != nil {
		return nil, fmt.Errorf("could not make proposals: could not read block from ledger at round %v: %v", round, err)
	}

	b := bookkeeping.MakeBlock(prev)
	b.RewardsState = prev.RewardsState
	return validatedBlock{blk: &b}, nil
}

// WithSeed implements the agreement.ValidatedBlock interface.
func (ve validatedBlock) WithSeed(s committee.Seed) agreement.ValidatedBlock {
	newblock := ve.blk.WithSeed(s)
	return validatedBlock{blk: &newblock}
}

// Block implements the agreement.ValidatedBlock interface.
func (ve validatedBlock) Block() bookkeeping.Block {
	return *ve.blk
}

type ledgerImpl struct {
	l *data.Ledger
}

// NextRound implements Ledger.NextRound.
func (i ledgerImpl) NextRound() basics.Round {
	return i.l.NextRound()
}

func (i ledgerImpl) Seed(r basics.Round) (committee.Seed, error) {
	block, err := i.l.BlockHdr(r)
	if err != nil {
		return committee.Seed{}, err
	}
	return block.Seed, nil
}

func (i ledgerImpl) LookupDigest(r basics.Round) (crypto.Digest, error) {
	blockhdr, err := i.l.BlockHdr(r)
	if err != nil {
		return crypto.Digest{}, err
	}
	return crypto.Digest(blockhdr.Hash()), nil
}

// Lookup implements Ledger.Lookup.
func (i ledgerImpl) Lookup(r basics.Round, addr basics.Address) (basics.AccountData, error) {
	return i.l.Lookup(r, addr)
}

// Circulation implements Ledger.Circulation.
func (i ledgerImpl) Circulation(r basics.Round) (basics.MicroAlgos, error) {
	return i.l.Circulation(r)
}

// Wait implements Ledger.Wait.
func (i ledgerImpl) Wait(r basics.Round) chan struct{} {
	return i.l.Wait(r)
}

// EnsureValidatedBlock implements Ledger.EnsureValidatedBlock.
func (i ledgerImpl) EnsureValidatedBlock(e agreement.ValidatedBlock, c agreement.Certificate) {
	i.l.EnsureBlock(e.(validatedBlock).blk, c)
}

// EnsureBlock implements Ledger.EnsureBlock.
func (i ledgerImpl) EnsureBlock(e bookkeeping.Block, c agreement.Certificate) {
	i.l.EnsureBlock(&e, c)
}

// ConsensusParams implements Ledger.ConsensusParams.
func (i ledgerImpl) ConsensusParams(r basics.Round) (config.ConsensusParams, error) {
	return i.l.ConsensusParams(r)
}

// ConsensusParams implements Ledger.ConsensusVersion.
func (i ledgerImpl) ConsensusVersion(r basics.Round) (protocol.ConsensusVersion, error) {
	return i.l.ConsensusVersion(r)
}

// EnsureDigest implements Ledger.EnsureDigest.
func (i ledgerImpl) EnsureDigest(cert agreement.Certificate, verifier *agreement.AsyncVoteVerifier) {
	r := cert.Round
	consistencyCheck := func() bool {
		if r < i.NextRound() {
			b, err := i.l.Block(r)
			if err != nil {
				panic(err)
			}

			if b.Digest() != cert.Proposal.BlockDigest {
				err := fmt.Errorf("testLedger.EnsureDigest called with conflicting entries in round %v", r)
				panic(err)
			}
			return true
		}
		return false
	}

	if consistencyCheck() {
		return
	}
}
