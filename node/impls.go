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

package node

import (
	"context"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util/execpool"
)

// TODO these implementations should be pushed down into the corresponding structs or alternatively turned into new structs in the correct subpackages

const blockQueryPeerLimit = 10

type blockAuthenticatorImpl struct {
	*data.Ledger
	*agreement.AsyncVoteVerifier
}

func (i blockAuthenticatorImpl) Authenticate(block *bookkeeping.Block, cert *agreement.Certificate) error {
	return cert.Authenticate(*block, i.Ledger, i.AsyncVoteVerifier)
}

func (i blockAuthenticatorImpl) Quit() {
	i.AsyncVoteVerifier.Quit()
}

type blockValidatorImpl struct {
	l                *data.Ledger
	tp               *pools.TransactionPool
	verificationPool execpool.BacklogPool
}

// Validate implements BlockValidator.Validate.
func (i blockValidatorImpl) Validate(ctx context.Context, e bookkeeping.Block) (agreement.ValidatedBlock, error) {
	b := &e
	lvb, err := i.l.Validate(ctx, *b, i.tp, i.verificationPool)
	if err != nil {
		return nil, err
	}

	return validatedBlock{vb: lvb}, nil
}

type blockFactoryImpl struct {
	l                *data.Ledger
	tp               *pools.TransactionPool
	logStats         bool
	verificationPool execpool.BacklogPool
}

func makeBlockFactory(l *data.Ledger, tp *pools.TransactionPool, logStats bool, executionPool execpool.BacklogPool) *blockFactoryImpl {
	bf := &blockFactoryImpl{
		l:                l,
		tp:               tp,
		logStats:         logStats,
		verificationPool: executionPool,
	}
	return bf
}

// AssembleBlock implements Ledger.AssembleBlock.
func (i *blockFactoryImpl) AssembleBlock(round basics.Round, deadline time.Time) (agreement.ValidatedBlock, error) {
	start := time.Now()
	prev, err := i.l.BlockHdr(round - 1)
	if err != nil {
		return nil, fmt.Errorf("could not make proposals at round %d: could not read block from ledger: %v", round, err)
	}

	newEmptyBlk := bookkeeping.MakeBlock(prev)

	eval, err := i.l.StartEvaluator(newEmptyBlk.BlockHeader, i.tp, i.verificationPool)
	if err != nil {
		return nil, fmt.Errorf("could not make proposals at round %d: could not start evaluator: %v", round, err)
	}

	var stats telemetryspec.AssembleBlockMetrics
	stats.AssembleBlockStats = i.l.AssemblePayset(i.tp, eval, deadline)

	// Measure time here because we want to know how close to deadline we are
	dt := time.Now().Sub(start)
	stats.AssembleBlockStats.Nanoseconds = dt.Nanoseconds()

	lvb, err := eval.GenerateBlock()
	if err != nil {
		return nil, fmt.Errorf("could not make proposals at round %d: could not finish evaluator: %v", round, err)
	}

	if i.logStats {
		var details struct {
			Round uint64
		}
		details.Round = uint64(round)
		logging.Base().Metrics(telemetryspec.Transaction, stats, details)
	}

	return validatedBlock{vb: lvb}, nil
}

// validatedBlock satisfies agreement.ValidatedBlock
type validatedBlock struct {
	vb *ledger.ValidatedBlock
}

// WithSeed satisfies the agreement.ValidatedBlock interface.
func (vb validatedBlock) WithSeed(s committee.Seed) agreement.ValidatedBlock {
	lvb := vb.vb.WithSeed(s)
	return validatedBlock{vb: &lvb}
}

// Block satisfies the agreement.ValidatedBlock interface.
func (vb validatedBlock) Block() bookkeeping.Block {
	blk := vb.vb.Block()
	return blk
}

// agreementLedger implements the agreement.Ledger interface.
type agreementLedger struct {
	*data.Ledger

	ff rpcs.FetcherFactory
	n  network.GossipNode
}

// EnsureBlock implements agreement.LedgerWriter.EnsureBlock.
func (l agreementLedger) EnsureBlock(e bookkeeping.Block, c agreement.Certificate) {
	l.Ledger.EnsureBlock(&e, c)
}

// EnsureValidatedBlock implements agreement.LedgerWriter.EnsureValidatedBlock.
func (l agreementLedger) EnsureValidatedBlock(ve agreement.ValidatedBlock, c agreement.Certificate) {
	l.Ledger.EnsureValidatedBlock(ve.(validatedBlock).vb, c)
}

// EnsureDigest implements agreement.LedgerWriter.EnsureDigest.
// TODO: Get rid of EnsureDigest -- instead the ledger should expose what blocks it's waiting on, and a separate service should fetch them and call EnsureBlock
// should "retry until cert matches" logic live here or in the abstract fetcher?
func (l agreementLedger) EnsureDigest(cert agreement.Certificate, quit chan struct{}, verifier *agreement.AsyncVoteVerifier) {
	round := cert.Round
	blockHash := bookkeeping.BlockHash(cert.Proposal.BlockDigest) // semantic digest (i.e., hash of the block header), not byte-for-byte digest
	logging.Base().Debug("consensus was reached on a block we don't have yet: ", blockHash)
	for {
		// Ask the fetcher to get the block somehow
		block, fetchedCert, err := l.FetchBlockByDigest(round, quit)
		if err != nil {
			select {
			case <-quit:
				logging.Base().Debugf("EnsureDigest was asked to quit before we could acquire the block")
				return
			default:
			}
			logging.Base().Panicf("EnsureDigest could not acquire block, fetcher errored out: %v", err)
		}

		if block.Hash() == blockHash && block.ContentsMatchHeader() {
			l.EnsureBlock(block, cert)
			return
		}
		// Otherwise, fetcher gave us the wrong block
		logging.Base().Warnf("fetcher gave us bad/wrong block (for round %d): fetched hash %v; want hash %v", round, block.Hash(), blockHash)

		// As a failsafe, if the cert we fetched is valid but for the wrong block, panic as loudly as possible
		if cert.Round == fetchedCert.Round &&
			cert.Proposal.BlockDigest != fetchedCert.Proposal.BlockDigest &&
			fetchedCert.Authenticate(block, l, verifier) == nil {
			s := "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			s += "!!!!!!!!!! FORK DETECTED !!!!!!!!!!!\n"
			s += "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			s += "EnsureDigest called with a cert authenticating block with hash %v.\n"
			s += "We fetched a valid cert authenticating a different block, %v. This indicates a fork.\n\n"
			s += "Cert from our agreement service:\n%#v\n\n"
			s += "Cert from the fetcher:\n%#v\n\n"
			s += "Block from the fetcher:\n%#v\n\n"
			s += "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			s += "!!!!!!!!!! FORK DETECTED !!!!!!!!!!!\n"
			s += "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			s = fmt.Sprintf(s, cert.Proposal.BlockDigest, fetchedCert.Proposal.BlockDigest, cert, fetchedCert, block)
			fmt.Println(s)
			logging.Base().Error(s)
		}
	}
}

func (l agreementLedger) innerFetch(fetcher rpcs.Fetcher, round basics.Round, quit chan struct{}) (*bookkeeping.Block, *agreement.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcs.DefaultFetchTimeout)
	defer cancel()
	type fbreturn struct {
		block *bookkeeping.Block
		cert  *agreement.Certificate
		err   error
	}
	localdone := make(chan fbreturn, 1)
	go func() {
		block, cert, _, err := fetcher.FetchBlock(ctx, round)
		localdone <- fbreturn{block, cert, err}
	}()
	select {
	case ret := <-localdone:
		return ret.block, ret.cert, ret.err
	case <-quit:
		return nil, nil, nil
	case <-l.Wait(round):
		return nil, nil, nil
	}
}

// FetchBlockByDigest is a helper for EnsureDigest.
// TODO This is a kludge. Instead we should have a service that sees what the ledger is waiting on, fetches it, and calls EnsureBlock on it.
// TODO this doesn't actually use the digest from cert!
func (l agreementLedger) FetchBlockByDigest(round basics.Round, quit chan struct{}) (bookkeeping.Block, agreement.Certificate, error) {
	fetcher := l.ff.NewOverGossip(protocol.UniEnsBlockReqTag)
	defer func() {
		fetcher.Close()
	}()
	for {
		if fetcher.OutOfPeers(round) {
			fetcher.Close()
			// refresh peers and try again
			logging.Base().Warn("fetchBlockByDigest found no outgoing peers")
			l.n.RequestConnectOutgoing(true, quit)
			fetcher = l.ff.NewOverGossip(protocol.UniEnsBlockReqTag)
		}
		block, cert, err := l.innerFetch(fetcher, round, quit)
		if err == nil {
			if block == nil || cert == nil {
				// nil error, nil block = async write
				logging.Base().Debugf("async write of block from round %v to ledger (or quit)", round)
				return l.BlockCert(round) // err is nil because ledger.Wait returned
			}
			return *block, *cert, nil
		}
		select {
		case <-quit:
			return bookkeeping.Block{}, agreement.Certificate{}, fmt.Errorf("asked to abort")
		default:
			logging.Base().Debugf("error fetching block (%v), trying again", err)
			// todo: consider rate-limiting here if a node is completely offline.
		}
	}
}
