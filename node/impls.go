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

package node

import (
	"context"
	"errors"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
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
	verificationPool execpool.BacklogPool
}

// Validate implements BlockValidator.Validate.
func (i blockValidatorImpl) Validate(ctx context.Context, e bookkeeping.Block) (agreement.ValidatedBlock, error) {
	b := &e
	lvb, err := i.l.Validate(ctx, *b, i.verificationPool)
	if err != nil {
		return nil, err
	}

	return validatedBlock{vb: lvb}, nil
}

// agreementLedger implements the agreement.Ledger interface.
type agreementLedger struct {
	*data.Ledger
	UnmatchedPendingCertificates chan catchup.PendingUnmatchedCertificate
	n                            network.GossipNode
}

func makeAgreementLedger(ledger *data.Ledger, net network.GossipNode) agreementLedger {
	return agreementLedger{
		Ledger:                       ledger,
		UnmatchedPendingCertificates: make(chan catchup.PendingUnmatchedCertificate, 1),
		n:                            net,
	}
}

// EnsureBlock implements agreement.LedgerWriter.EnsureBlock.
func (l agreementLedger) EnsureBlock(e bookkeeping.Block, c agreement.Certificate) {
	l.Ledger.EnsureBlock(&e, c)
	// let the network know that we've made some progress.
	l.n.OnNetworkAdvance()
}

// EnsureValidatedBlock implements agreement.LedgerWriter.EnsureValidatedBlock.
func (l agreementLedger) EnsureValidatedBlock(ve agreement.ValidatedBlock, c agreement.Certificate) {
	l.Ledger.EnsureValidatedBlock(ve.(validatedBlock).vb, c)
	// let the network know that we've made some progress.
	l.n.OnNetworkAdvance()
}

// EnsureDigest implements agreement.LedgerWriter.EnsureDigest.
func (l agreementLedger) EnsureDigest(cert agreement.Certificate, verifier *agreement.AsyncVoteVerifier) {
	// let the network know that we've made some progress.
	// this might be controverasl since we haven't received the entire block, but we did get the
	// certificate, which means that network connections are likely to be just fine.
	l.n.OnNetworkAdvance()

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

// Wrapping error with a LedgerDroppedRoundError when an old round is requested but the ledger has already dropped the entry
func (l agreementLedger) Lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	record, err := l.Ledger.Lookup(rnd, addr)
	var e *ledger.RoundOffsetError
	if errors.As(err, &e) {
		err = &agreement.LedgerDroppedRoundError{
			Err: err,
		}
	}
	return record, err
}
