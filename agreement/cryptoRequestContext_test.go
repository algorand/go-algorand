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

package agreement

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
)

func TestCryptoRequestContextAddCancelRound(t *testing.T) {
	pending := makePendingRequestsContext()
	req := cryptoRequest{Round: 10, Period: 10}
	ctx := pending.add(req)

	roundCtx, hasRound := pending[req.Round]
	require.True(t, hasRound)

	_, hasPeriod := pending[req.Round].periods[cryptoRequestCtxKey{period: req.Period}]
	require.True(t, hasPeriod)

	roundCtx.cancel()
	select {
	case <-ctx.Done():
	default:
		t.Errorf("did not cancel request")
	}
}

func TestCryptoRequestContextAddCancelPeriod(t *testing.T) {
	pending := makePendingRequestsContext()
	req := cryptoRequest{Round: 10, Period: 10}
	ctx := pending.add(req)

	_, hasRound := pending[req.Round]
	require.True(t, hasRound)

	periodCtx, hasPeriod := pending[req.Round].periods[cryptoRequestCtxKey{period: req.Period}]
	require.True(t, hasPeriod)

	periodCtx.cancel()
	select {
	case <-ctx.Done():
	default:
		t.Errorf("did not cancel request")
	}
}

func TestCryptoRequestContextAddCancelProposal(t *testing.T) {
	pending := makePendingRequestsContext()
	proposal := cryptoRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: 10, Period: 10}
	ctx := pending.add(proposal)

	proposal2 := cryptoRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: 10, Period: 10}
	ctx2 := pending.add(proposal2)

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
	pending := makePendingRequestsContext()
	proposal := cryptoRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: 10, Pinned: true}
	ctx := pending.add(proposal)

	proposal2 := cryptoRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: 10, Pinned: true}
	ctx2 := pending.add(proposal2)

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
	pending := makePendingRequestsContext()
	proposal := cryptoRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: 10, Pinned: true}
	ctx := pending.add(proposal)

	proposal2 := cryptoRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: 10, Period: 10}
	ctx2 := pending.add(proposal2)

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
	pending := makePendingRequestsContext()
	proposal := cryptoRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: 10, Period: 10}
	ctx := pending.add(proposal)

	proposal2 := cryptoRequest{message: message{Tag: protocol.ProposalPayloadTag}, Round: 10, Pinned: true}
	ctx2 := pending.add(proposal2)

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
	pending := makePendingRequestsContext()
	req := cryptoRequest{Round: 10, Period: 10}
	ctx := pending.add(req)

	_, hasRound := pending[req.Round]
	require.True(t, hasRound)

	_, hasPeriod := pending[req.Round].periods[cryptoRequestCtxKey{period: req.Period}]
	require.True(t, hasPeriod)

	pending.clearStaleContexts(11, 20, false)
	select {
	case <-ctx.Done():
		t.Errorf("cancelled request")
	default:
	}

	pending.clearStaleContexts(12, 20, false)
	select {
	case <-ctx.Done():
	default:
		t.Errorf("did not cancel request")
	}

	_, hasRound = pending[req.Round]
	require.False(t, hasRound)

	_, hasPeriod = pending[req.Round].periods[cryptoRequestCtxKey{period: req.Period}]
	require.False(t, hasPeriod)
}

func TestCryptoRequestContextCleanupByRoundPinned(t *testing.T) {
	pending := makePendingRequestsContext()
	req := cryptoRequest{Round: 10, Pinned: true}
	ctx := pending.add(req)

	_, hasRound := pending[req.Round]
	require.True(t, hasRound)

	_, hasPeriod := pending[req.Round].periods[cryptoRequestCtxKey{pinned: req.Pinned}]
	require.True(t, hasPeriod)

	pending.clearStaleContexts(11, 20, false)
	select {
	case <-ctx.Done():
		t.Errorf("cancelled request")
	default:
	}

	pending.clearStaleContexts(12, 20, false)
	select {
	case <-ctx.Done():
	default:
		t.Errorf("did not cancel request")
	}

	_, hasRound = pending[req.Round]
	require.False(t, hasRound)

	_, hasPeriod = pending[req.Round].periods[cryptoRequestCtxKey{pinned: req.Pinned}]
	require.False(t, hasPeriod)
}

func TestCryptoRequestContextCleanupByPeriod(t *testing.T) {
	pending := makePendingRequestsContext()
	req := cryptoRequest{Round: 10, Period: 10}
	ctx := pending.add(req)

	_, hasRound := pending[req.Round]
	require.True(t, hasRound)

	_, hasPeriod := pending[req.Round].periods[cryptoRequestCtxKey{period: req.Period}]
	require.True(t, hasPeriod)

	pending.clearStaleContexts(10, 12, false)
	select {
	case <-ctx.Done():
		t.Errorf("cancelled request")
	default:
	}

	pending.clearStaleContexts(10, 13, true)
	select {
	case <-ctx.Done():
		t.Errorf("cancelled request via pinned")
	default:
	}

	pending.clearStaleContexts(10, 13, false)
	select {
	case <-ctx.Done():
	default:
		t.Errorf("did not cancel request")
	}

	_, hasRound = pending[req.Round]
	require.False(t, hasRound)

	_, hasPeriod = pending[req.Round].periods[cryptoRequestCtxKey{period: req.Period}]
	require.False(t, hasPeriod)
}

func TestCryptoRequestContextCleanupByPeriodPinned(t *testing.T) {
	pending := makePendingRequestsContext()
	req := cryptoRequest{Round: 10, Pinned: true}
	ctx := pending.add(req)

	_, hasRound := pending[req.Round]
	require.True(t, hasRound)

	_, hasPeriod := pending[req.Round].periods[cryptoRequestCtxKey{pinned: req.Pinned}]
	require.True(t, hasPeriod)

	pending.clearStaleContexts(10, 12, false)
	select {
	case <-ctx.Done():
		t.Errorf("cancelled request")
	default:
	}

	pending.clearStaleContexts(10, 13, false)
	select {
	case <-ctx.Done():
		t.Errorf("cancelled request but pinned")
	default:
	}
}
