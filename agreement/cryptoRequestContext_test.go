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

package agreement

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testPartitioning"
)

func forEachTagDo(fn func(protocol.Tag)) {
	for _, tag := range []protocol.Tag{protocol.AgreementVoteTag, protocol.ProposalPayloadTag, protocol.VoteBundleTag} {
		fn(tag)
	}
}

func TestCryptoRequestContextAddCancelRound(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)
	per := period(10)
	forEachTagDo(func(tag protocol.Tag) {
		var ctx context.Context
		switch tag {
		case protocol.AgreementVoteTag:
			req := cryptoVoteRequest{Round: rnd, Period: per}
			ctx = pending.addVote(req)
		case protocol.ProposalPayloadTag:
			req := cryptoProposalRequest{Round: rnd, Period: per}
			ctx = pending.addProposal(req)
		case protocol.VoteBundleTag:
			req := cryptoBundleRequest{Round: rnd, Period: per}
			ctx = pending.addBundle(req)
		}

		roundCtx, hasRound := pending[rnd]
		require.True(t, hasRound)

		_, hasPeriod := pending[rnd].periods[cryptoRequestCtxKey{period: per}]
		require.True(t, hasPeriod)

		roundCtx.cancel()
		select {
		case <-ctx.Done():
		default:
			t.Errorf("did not cancel request")
		}
	})
}

func TestCryptoRequestContextAddCancelPeriod(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)
	per := period(10)

	forEachTagDo(func(tag protocol.Tag) {
		var ctx context.Context
		switch tag {
		case protocol.AgreementVoteTag:
			req := cryptoVoteRequest{Round: rnd, Period: per}
			ctx = pending.addVote(req)
		case protocol.ProposalPayloadTag:
			req := cryptoProposalRequest{Round: rnd, Period: per}
			ctx = pending.addProposal(req)
		case protocol.VoteBundleTag:
			req := cryptoBundleRequest{Round: rnd, Period: per}
			ctx = pending.addBundle(req)
		}

		_, hasRound := pending[rnd]
		require.True(t, hasRound)

		periodCtx, hasPeriod := pending[rnd].periods[cryptoRequestCtxKey{period: per}]
		require.True(t, hasPeriod)

		periodCtx.cancel()
		select {
		case <-ctx.Done():
		default:
			t.Errorf("did not cancel request")
		}
	})
}

func TestCryptoRequestContextAddCancelProposal(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)
	per := period(10)
	proposal := cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: rnd, Period: per}
	ctx := pending.addProposal(proposal)

	proposal2 := cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: rnd, Period: per}
	ctx2 := pending.addProposal(proposal2)

	select {
	case <-ctx.Done():
	default:
		t.Errorf("did not cancel request")
	}

	select {
	case <-ctx2.Done():
		t.Errorf("cancelled request")
	default:
	}

}

func TestCryptoRequestContextAddCancelPinnedProposal(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)
	proposal := cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: rnd, Pinned: true}
	ctx := pending.addProposal(proposal)

	proposal2 := cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: rnd, Pinned: true}
	ctx2 := pending.addProposal(proposal2)

	select {
	case <-ctx.Done():
	default:
		t.Errorf("did not cancel request")
	}

	select {
	case <-ctx2.Done():
		t.Errorf("cancelled request")
	default:
	}

}

func TestCryptoRequestContextAddNoCancelPinnedProposal(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)
	per := period(10)
	proposal := cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: rnd, Pinned: true}
	ctx := pending.addProposal(proposal)

	proposal2 := cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: rnd, Period: per}
	ctx2 := pending.addProposal(proposal2)

	select {
	case <-ctx.Done():
		t.Errorf("cancelled pinned request")
	default:
	}

	select {
	case <-ctx2.Done():
		t.Errorf("cancelled request")
	default:
	}
}

func TestCryptoRequestContextAddNoInterferencePinnedProposal(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)
	per := period(10)
	proposal := cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: rnd, Period: per}
	ctx := pending.addProposal(proposal)

	proposal2 := cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: rnd, Pinned: true}
	ctx2 := pending.addProposal(proposal2)

	select {
	case <-ctx.Done():
		t.Errorf("pinned request cancelled non-pinned request")
	default:
	}

	select {
	case <-ctx2.Done():
		t.Errorf("cancelled pinned request")
	default:
	}
}

func TestCryptoRequestContextCleanupByRound(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)
	per := period(10)

	forEachTagDo(func(tag protocol.Tag) {
		var ctx context.Context
		switch tag {
		case protocol.AgreementVoteTag:
			req := cryptoVoteRequest{Round: rnd, Period: per}
			ctx = pending.addVote(req)
		case protocol.ProposalPayloadTag:
			req := cryptoProposalRequest{Round: rnd, Period: per}
			ctx = pending.addProposal(req)
		case protocol.VoteBundleTag:
			req := cryptoBundleRequest{Round: rnd, Period: per}
			ctx = pending.addBundle(req)
		}

		_, hasRound := pending[rnd]
		require.True(t, hasRound)

		_, hasPeriod := pending[rnd].periods[cryptoRequestCtxKey{period: per}]
		require.True(t, hasPeriod)

		pending.clearStaleContexts(rnd+1, 20, false, false)
		select {
		case <-ctx.Done():
			t.Errorf("cancelled request")
		default:
		}

		pending.clearStaleContexts(rnd+2, 20, false, false)
		select {
		case <-ctx.Done():
		default:
			t.Errorf("did not cancel request")
		}

		_, hasRound = pending[rnd]
		require.False(t, hasRound)

		_, hasPeriod = pending[rnd].periods[cryptoRequestCtxKey{period: per}]
		require.False(t, hasPeriod)
	})
}

func TestCryptoRequestContextCleanupByRoundPinnedCertify(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)

	forEachTagDo(func(tag protocol.Tag) {
		var ctx context.Context
		var hasRound, hasPeriod bool
		switch tag {
		case protocol.AgreementVoteTag:
			return
		case protocol.ProposalPayloadTag:
			req := cryptoProposalRequest{Round: rnd, Pinned: true}
			ctx = pending.addProposal(req)

			_, hasRound = pending[rnd]
			require.True(t, hasRound)

			_, hasPeriod = pending[rnd].periods[cryptoRequestCtxKey{pinned: true}]
			require.True(t, hasPeriod)

		case protocol.VoteBundleTag:
			req := cryptoBundleRequest{Round: rnd, Certify: true}
			ctx = pending.addBundle(req)

			_, hasRound = pending[rnd]
			require.True(t, hasRound)

			_, hasPeriod = pending[rnd].periods[cryptoRequestCtxKey{certify: true}]
			require.True(t, hasPeriod)
		}

		pending.clearStaleContexts(rnd+1, 20, false, false)
		select {
		case <-ctx.Done():
			t.Errorf("cancelled request")
		default:
		}

		pending.clearStaleContexts(rnd+2, 20, false, false)
		select {
		case <-ctx.Done():
		default:
			t.Errorf("did not cancel request")
		}

		_, hasRound = pending[rnd]
		require.False(t, hasRound)

		switch tag {
		case protocol.AgreementVoteTag:
			return
		case protocol.ProposalPayloadTag:
			_, hasPeriod = pending[rnd].periods[cryptoRequestCtxKey{pinned: true}]
			require.False(t, hasPeriod)
		case protocol.VoteBundleTag:
			_, hasPeriod = pending[rnd].periods[cryptoRequestCtxKey{certify: true}]
			require.False(t, hasPeriod)
		}
	})
}

func TestCryptoRequestContextCleanupByPeriod(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)
	per := period(10)

	forEachTagDo(func(tag protocol.Tag) {
		var ctx context.Context
		switch tag {
		case protocol.AgreementVoteTag:
			req := cryptoVoteRequest{Round: rnd, Period: per}
			ctx = pending.addVote(req)
		case protocol.ProposalPayloadTag:
			req := cryptoProposalRequest{Round: rnd, Period: per}
			ctx = pending.addProposal(req)
		case protocol.VoteBundleTag:
			req := cryptoBundleRequest{Round: rnd, Period: per}
			ctx = pending.addBundle(req)
		}

		_, hasRound := pending[rnd]
		require.True(t, hasRound)

		_, hasPeriod := pending[rnd].periods[cryptoRequestCtxKey{period: per}]
		require.True(t, hasPeriod)

		pending.clearStaleContexts(rnd, per+2, false, false)
		select {
		case <-ctx.Done():
			t.Errorf("cancelled request")
		default:
		}

		pending.clearStaleContexts(rnd, per+3, true, false)
		select {
		case <-ctx.Done():
			t.Errorf("cancelled request via pinned")
		default:
		}

		pending.clearStaleContexts(rnd, per+3, false, true)
		select {
		case <-ctx.Done():
			t.Errorf("cancelled request via certify")
		default:
		}

		pending.clearStaleContexts(rnd, per+3, false, false)
		select {
		case <-ctx.Done():
		default:
			t.Errorf("did not cancel request")
		}

		_, hasRound = pending[rnd]
		require.False(t, hasRound)

		_, hasPeriod = pending[rnd].periods[cryptoRequestCtxKey{period: per}]
		require.False(t, hasPeriod)
	})
}

func TestCryptoRequestContextCleanupByPeriodPinned(t *testing.T) {
	testPartitioning.PartitionTest(t)

	pending := makePendingRequestsContext()
	rnd := round(10)

	forEachTagDo(func(tag protocol.Tag) {
		var ctx context.Context
		switch tag {
		case protocol.AgreementVoteTag:
			return
		case protocol.ProposalPayloadTag:
			req := cryptoProposalRequest{Round: rnd, Pinned: true}
			ctx = pending.addProposal(req)

			_, hasRound := pending[rnd]
			require.True(t, hasRound)

			_, hasPeriod := pending[rnd].periods[cryptoRequestCtxKey{pinned: req.Pinned}]
			require.True(t, hasPeriod)

		case protocol.VoteBundleTag:
			req := cryptoBundleRequest{Round: rnd, Certify: true}
			ctx = pending.addBundle(req)

			_, hasRound := pending[rnd]
			require.True(t, hasRound)

			_, hasPeriod := pending[rnd].periods[cryptoRequestCtxKey{certify: req.Certify}]
			require.True(t, hasPeriod)
		}

		pending.clearStaleContexts(rnd, 12, false, false)
		select {
		case <-ctx.Done():
			t.Errorf("cancelled request")
		default:
		}

		pending.clearStaleContexts(rnd, 13, false, false)
		select {
		case <-ctx.Done():
			t.Errorf("cancelled request but pinned/certify set")
		default:
		}
	})
}
