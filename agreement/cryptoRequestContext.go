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
	"context"

	"github.com/algorand/go-algorand/protocol"
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
	pinned bool // If this is set, period should be 0.
}

// roundRequestsContext keeps a the root context for all cryptoRequests associated with a round.
type roundRequestsContext struct {
	ctx     context.Context
	cancel  context.CancelFunc
	periods map[cryptoRequestCtxKey]periodRequestsContext
}

// pendingRequests keeps the context for all pending requests
type pendingRequestsContext map[round]roundRequestsContext

func makePendingRequestsContext() pendingRequestsContext {
	return make(map[round]roundRequestsContext)
}

// add returns a context associated with a given request
func (pending pendingRequestsContext) add(request cryptoRequest) context.Context {
	// create round context
	if _, has := pending[request.Round]; !has {
		roundCtx, cancel := context.WithCancel(context.Background())
		pending[request.Round] = roundRequestsContext{ctx: roundCtx, cancel: cancel, periods: make(map[cryptoRequestCtxKey]periodRequestsContext)}
	}

	pkey := cryptoRequestCtxKey{period: request.Period}
	if request.Pinned {
		pkey = cryptoRequestCtxKey{pinned: request.Pinned}
	}

	// create period context
	if _, has := pending[request.Round].periods[pkey]; !has {
		periodCtx, periodCancel := context.WithCancel(pending[request.Round].ctx)
		pending[request.Round].periods[pkey] = periodRequestsContext{ctx: periodCtx, cancel: periodCancel}
	}

	// find the right context for the request
	roundCtx := pending[request.Round]
	periodCtx, has := roundCtx.periods[pkey]

	if request.Tag == protocol.ProposalPayloadTag {
		// we have a new proposal, so cancel validation of an old proposal for the same round and period
		if has && periodCtx.proposalCancelFunc != nil {
			periodCtx.proposalCancelFunc()
		}

		// create a context for the new proposal
		var proposalContext context.Context
		proposalContext, periodCtx.proposalCancelFunc = context.WithCancel(periodCtx.ctx)
		pending[request.Round].periods[pkey] = periodCtx
		return proposalContext
	}
	return periodCtx.ctx
}

// add returns a context associated with a given request
func (pending pendingRequestsContext) addVote(request cryptoVoteRequest) context.Context {
	// create round context
	if _, has := pending[request.Round]; !has {
		roundCtx, cancel := context.WithCancel(context.Background())
		pending[request.Round] = roundRequestsContext{ctx: roundCtx, cancel: cancel, periods: make(map[cryptoRequestCtxKey]periodRequestsContext)}
	}

	pkey := cryptoRequestCtxKey{period: request.Period}
	if request.Pinned {
		pkey = cryptoRequestCtxKey{pinned: request.Pinned}
	}

	// create period context
	if _, has := pending[request.Round].periods[pkey]; !has {
		periodCtx, periodCancel := context.WithCancel(pending[request.Round].ctx)
		pending[request.Round].periods[pkey] = periodRequestsContext{ctx: periodCtx, cancel: periodCancel}
	}

	// find the right context for the request
	roundCtx := pending[request.Round]
	periodCtx := roundCtx.periods[pkey]
	return periodCtx.ctx
}

// clearStaleContexts cancels contexts associated with cryptoRequests that are no longer relevant at the given round and period
func (pending pendingRequestsContext) clearStaleContexts(r round, p period, pinned bool) {
	// at round r + 2 we can clear tasks from round r
	oldRounds := make([]round, 0)
	for round := range pending {
		if round+2 <= r {
			oldRounds = append(oldRounds, round)
		}
	}

	// we got a new pinned proposal: do not clear period tasks
	if pinned {
		return
	}

	// at period p + 3 we can clear tasks from period p
	for _, oldRound := range oldRounds {
		pending[oldRound].cancel()
		delete(pending, oldRound)
	}

	if _, has := pending[r]; has {
		oldPeriods := make([]cryptoRequestCtxKey, 0)
		for pkey := range pending[r].periods {
			if !pkey.pinned && pkey.period+3 <= p {
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
