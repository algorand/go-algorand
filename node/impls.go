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

package node

import (
	"context"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/util/execpool"
)

// TODO these implementations should be pushed down into the corresponding structs or alternatively turned into new structs in the correct subpackages

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

	eval, err := i.l.StartEvaluator(newEmptyBlk.BlockHeader)
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
	UnmatchedPendingCertificates chan catchup.PendingUnmatchedCertificate
}

func makeAgreementLedger(ledger *data.Ledger) agreementLedger {
	return agreementLedger{
		Ledger:                       ledger,
		UnmatchedPendingCertificates: make(chan catchup.PendingUnmatchedCertificate, 1),
	}
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
func (l agreementLedger) EnsureDigest(cert agreement.Certificate, verifier *agreement.AsyncVoteVerifier) {
	// clear out the pending certificates ( if any )
	select {
	case pendingCert := <-l.UnmatchedPendingCertificates:
		logging.Base().Debugf("agreementLedger.EnsureDigest has flushed out pending request for certificate for round %d in favor of recent certificate for round %d", pendingCert.Cert.Round, cert.Round)
	default:
	}

	// The channel send to UnmatchedPendingCertificates is guaranteed to be non-blocking since due to the fact that -
	// 1. the channel capacity is 1
	// 2. we just cleared a single item off this channel ( if there was any )
	// 3. the EnsureDigest method is being called with the agreeement service guarantee
	// 4. no other senders to this channel exists
	l.UnmatchedPendingCertificates <- catchup.PendingUnmatchedCertificate{Cert: cert, VoteVerifier: verifier}
}
