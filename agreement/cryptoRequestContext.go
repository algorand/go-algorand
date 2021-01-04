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
)

// periodRequestsContext keeps a context for all tasks associated with the same period, so we can cancel them if the period becomes irrelevant.
// A proposal's context is derived from the period, so we can cancel individual proposals until concluding on the highest-priority one.
type periodRequestsContext struct {
	ctx                context.Context
	cancel             context.CancelFunc
	proposalCancelFunc context.CancelFunc
}

// cryptoRequestCtxKey keys the map roundRequestsContext.periods.
//
// It allows for the pinned value to act as a sentinel.
type cryptoRequestCtxKey struct {
	period period

	// note: following two booleans are mutually exclusive
	certify bool // If this is set, period should be 0.
	pinned  bool // If this is set, period should be 0.
}

// roundRequestsContext keeps a the root context for all cryptoRequests associated with a round.
type roundRequestsContext struct {
	ctx     context.Context
	cancel  context.CancelFunc
	periods map[cryptoRequestCtxKey]periodRequestsContext
}

// pendingRequests keeps the context for all pending requests
//msgp:ignore pendingRequestsContext
type pendingRequestsContext map[round]roundRequestsContext

func makePendingRequestsContext() pendingRequestsContext {
	return make(map[round]roundRequestsContext)
}

// getReqCtx gets the roundRequestsContext for a round and cryptoRequestCtxKey.
func (pending pendingRequestsContext) getReqCtx(rnd round, pkey cryptoRequestCtxKey) periodRequestsContext {
	// create round context
	if _, has := pending[rnd]; !has {
		roundCtx, cancel := context.WithCancel(context.Background())
		pending[rnd] = roundRequestsContext{ctx: roundCtx, cancel: cancel, periods: make(map[cryptoRequestCtxKey]periodRequestsContext)}
	}

	// create period context
	if _, has := pending[rnd].periods[pkey]; !has {
		periodCtx, periodCancel := context.WithCancel(pending[rnd].ctx)
		pending[rnd].periods[pkey] = periodRequestsContext{ctx: periodCtx, cancel: periodCancel}
	}
	return pending[rnd].periods[pkey]
}

// addVote returns a context associated with a given request
func (pending pendingRequestsContext) addVote(request cryptoVoteRequest) context.Context {
	return pending.getReqCtx(request.Round, cryptoRequestCtxKey{period: request.Period}).ctx
}

// addProposal returns a context associated with a given request (and cancels any older similar request)
func (pending pendingRequestsContext) addProposal(request cryptoProposalRequest) context.Context {
	pkey := cryptoRequestCtxKey{period: request.Period}
	if request.Pinned {
		pkey = cryptoRequestCtxKey{pinned: request.Pinned}
	}
	rqctx := pending.getReqCtx(request.Round, pkey)

	if rqctx.proposalCancelFunc != nil {
		// we have a new proposal, so cancel validation of an old proposal for the same round and period
		rqctx.proposalCancelFunc()
	}

	// create a context for the new proposal
	var proposalContext context.Context
	proposalContext, rqctx.proposalCancelFunc = context.WithCancel(rqctx.ctx)
	pending[request.Round].periods[pkey] = rqctx
	return proposalContext
}

// addBundle returns a context associated with a given request
func (pending pendingRequestsContext) addBundle(request cryptoBundleRequest) context.Context {
	pkey := cryptoRequestCtxKey{period: request.Period}
	if request.Certify {
		pkey = cryptoRequestCtxKey{certify: request.Certify}
	}
	return pending.getReqCtx(request.Round, pkey).ctx
}

// clearStaleContexts cancels contexts associated with cryptoRequests that are no longer relevant at the given round and period
func (pending pendingRequestsContext) clearStaleContexts(r round, p period, pinned bool, certify bool) {
	// at round r + 2 we can clear tasks from round r
	oldRounds := make([]round, 0)
	for round := range pending {
		if round+2 <= r {
			oldRounds = append(oldRounds, round)
		}
	}
	for _, oldRound := range oldRounds {
		pending[oldRound].cancel()
		delete(pending, oldRound)
	}

	// we got a new pinned proposal or a cert bundle:
	// do not clear period tasks
	if pinned || certify {
		return
	}

	// at period p + 3 we can clear tasks from period p
	if _, has := pending[r]; has {
		oldPeriods := make([]cryptoRequestCtxKey, 0)
		for pkey := range pending[r].periods {
			if !pkey.pinned && !pkey.certify && pkey.period+3 <= p {
				oldPeriods = append(oldPeriods, pkey)
			}
		}

		for _, period := range oldPeriods {
			pending[r].periods[period].cancel()
			delete(pending[r].periods, period)
			if len(pending[r].periods) == 0 {
				delete(pending, r)
			}
		}
	}
}
