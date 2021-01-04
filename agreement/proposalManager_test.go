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
	"testing"

	"github.com/stretchr/testify/require"
)

// Creates a proposal manager, and returns it in automata and white box form, along
// with a vote creation helper. Need to pass in round for some contract logic...
func setupManager(t *testing.T, r round) (pWhite *proposalManager, pMachine ioAutomata, helper *voteMakerHelper) {
	// Set up a composed test machine starting at specified rps
	rRouter := new(rootRouter)
	rRouter.update(player{Round: r}, r, false)

	pMachine = &ioAutomataConcrete{
		listener:  rRouter.proposalRoot,
		routerCtx: rRouter,
		playerCtx: player{Round: r},
	}

	helper = &voteMakerHelper{}
	helper.Setup()
	pWhite = rRouter.proposalRoot.underlying().(*proposalManager)
	return
}

func TestProposalManagerThresholdSoftFastForward(t *testing.T) {
	// sanity check that manager tells underlings to fast forward new period
	const p = 1
	const r = 10
	_, pM, helper := setupManager(t, r)

	// create a soft threshold.
	pV := helper.MakeRandomProposalValue()
	b := helper.MakeUnauthenticatedBundle(t, r, p+3, soft, *pV)
	inMsg := thresholdEvent{
		T:        softThreshold,
		Bundle:   b,
		Round:    r,
		Period:   p + 3,
		Step:     soft,
		Proposal: *pV,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// check that the inner trace contains a boost period message
	nxtPeriodEvent := newPeriodEvent{Period: p + 3, Proposal: *pV}
	require.Truef(t, pM.getTraceVisible().Contains(nxtPeriodEvent),
		"Proposal Manager must tell lower level to fast forward period on soft threshold")
}

func TestProposalManagerThresholdSoftStage(t *testing.T) {
	// sanity check that manager tells underlings to deal with soft threshold
	const p = 1
	const r = 10
	_, pM, helper := setupManager(t, r)

	// create a soft threshold.
	pV := helper.MakeRandomProposalValue()
	b := helper.MakeUnauthenticatedBundle(t, r, p, soft, *pV)
	softThreshEvent := thresholdEvent{
		T:        softThreshold,
		Bundle:   b,
		Round:    r,
		Period:   p,
		Step:     soft,
		Proposal: *pV,
	}
	err, panicErr := pM.transition(softThreshEvent)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// check that the inner trace contains a forwarded soft threshold
	// (this is very much white box testing)
	count := 0
	require.Truef(t, pM.getTraceVisible().ContainsFn(func(b event) bool {
		if b.ComparableStr() == softThreshEvent.ComparableStr() {
			count++
		}
		if count > 1 {
			return true
		}
		return false
	}),
		"Proposal Manager must forward soft threshold to proposal round machine")
}

func TestProposalManagerThresholdCert(t *testing.T) {
	const p = 10
	const r = 1
	_, pM, helper := setupManager(t, r)

	// create a cert threshold.
	pV := helper.MakeRandomProposalValue()
	b := helper.MakeUnauthenticatedBundle(t, r, p, cert, *pV)
	inMsg := thresholdEvent{
		T:        certThreshold,
		Bundle:   b,
		Round:    r,
		Period:   p,
		Step:     cert,
		Proposal: *pV,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// check that the inner trace contains a forwarded cert threshold
	// (this is very much white box testing)
	count := 0
	require.Truef(t, pM.getTraceVisible().ContainsFn(func(b event) bool {
		if b.ComparableStr() == inMsg.ComparableStr() {
			count++
		}
		if count > 1 {
			return true
		}
		return false
	}),
		"Proposal Manager must forward cert threshold to proposal round machine")
}

func TestProposalManagerThresholdNext(t *testing.T) {
	// check that manager tells the Tracker to increase period +1
	const p = 10
	const r = 1
	_, pM, helper := setupManager(t, r)

	// create a next threshold.
	pV := helper.MakeRandomProposalValue()
	b := helper.MakeUnauthenticatedBundle(t, r, p, next, *pV)
	inMsg := thresholdEvent{
		T:        nextThreshold,
		Bundle:   b,
		Round:    r,
		Period:   p,
		Step:     next,
		Proposal: *pV,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// check that the inner trace contains a boost period message
	nxtPeriodEvent := newPeriodEvent{Period: p + 1, Proposal: *pV}
	require.Truef(t, pM.getTraceVisible().Contains(nxtPeriodEvent),
		"Proposal Manager must tell lower level to increment period")
}

func TestProposalManagerResetsRoundInterruption(t *testing.T) {
	// check that manager tells Store to increase round + 1
	const p = 10
	const r = 1
	_, pM, _ := setupManager(t, r)

	// create a newRound message. We may eventually want to offload this logic to the helper.
	err, panicErr := pM.transition(roundInterruptionEvent{Round: r + 2})
	require.NoError(t, err)
	require.NoError(t, panicErr)

	roundEv := newRoundEvent{}
	require.Truef(t, pM.getTraceVisible().Contains(roundEv),
		"Proposal Manager must tell lower level to increment round")
}

func TestProposalManagerRejectsUnknownEvent(t *testing.T) {
	// check that manager discards unknown events.
	_, pM, _ := setupManager(t, 0)

	// create a verified bundle
	inMsg := messageEvent{
		T:     bundleVerified,
		Input: message{},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.Errorf(t, panicErr, "proposalManager must reject bundleVerified event")
}

func TestProposalFreshAdjacentPeriods(t *testing.T) {
	// votes from periods that are non-adjacent to current period are not fresh
	// unfortunately, this is more of an end-to-end test as the proposeTracker will also filter
	const r = 100
	const p = 3
	const s = soft
	_, pM, helper := setupManager(t, r)
	b := testCaseBuilder{}
	currentPlayerState := freshnessData{
		PlayerRound:          r,
		PlayerPeriod:         p,
		PlayerStep:           s,
		PlayerLastConcluding: 0,
	}

	// generate vote in same round same period, should be fine
	pV := helper.MakeRandomProposalValue()
	uv := helper.MakeUnauthenticatedVote(t, 0, r, p, s, *pV)
	inMsg := filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: votePresent,
			Input: message{
				UnauthenticatedVote: uv,
			},
		},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// vote in same round p + 1 should also be fine
	pV = helper.MakeRandomProposalValue()
	uv = helper.MakeUnauthenticatedVote(t, 0, r, p+1, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: votePresent,
			Input: message{
				UnauthenticatedVote: uv,
			},
		},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// vote in same round p+ 2 should be filtered
	pV = helper.MakeRandomProposalValue()
	uv = helper.MakeUnauthenticatedVote(t, 0, r, p+2, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: votePresent,
			Input: message{
				UnauthenticatedVote: uv,
			},
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// vote in same round p - 2 should be filtered
	pV = helper.MakeRandomProposalValue()
	uv = helper.MakeUnauthenticatedVote(t, 0, r, p-2, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: votePresent,
			Input: message{
				UnauthenticatedVote: uv,
			},
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// vote in r + 1 should be filtered unless period 0
	pV = helper.MakeRandomProposalValue()
	uv = helper.MakeUnauthenticatedVote(t, 0, r+1, 1, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: votePresent,
			Input: message{
				UnauthenticatedVote: uv,
			},
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	pV = helper.MakeRandomProposalValue()
	uv = helper.MakeUnauthenticatedVote(t, 0, r+1, 0, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: votePresent,
			Input: message{
				UnauthenticatedVote: uv,
			},
		},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// vote > r + 1 should be filtered
	pV = helper.MakeRandomProposalValue()
	uv = helper.MakeUnauthenticatedVote(t, 0, r+2, 0, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: votePresent,
			Input: message{
				UnauthenticatedVote: uv,
			},
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	res, err := b.Build().Validate(pM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VotePresent accidentally filtered")
}

func TestProposalFreshAdjacentPeriodsVerified(t *testing.T) {
	// verbatim copy of above test case, but with verified votes
	// votes from periods that are non-adjacent to current period are not fresh
	// unfortunately, this is more of an end-to-end test as the proposeTracker will also filter
	const r = 129
	const p = 8
	const s = soft
	_, pM, helper := setupManager(t, r)
	b := testCaseBuilder{}
	currentPlayerState := freshnessData{
		PlayerRound:          r,
		PlayerPeriod:         p,
		PlayerStep:           s,
		PlayerLastConcluding: 0,
	}

	// generate vote in same round same period, should be fine
	pV := helper.MakeRandomProposalValue()
	v := helper.MakeVerifiedVote(t, 0, r, p, s, *pV)
	inMsg := filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: voteVerified,
			Input: message{
				UnauthenticatedVote: v.u(),
				Vote:                v,
			},
		},
	}
	b.AddInOutPair(inMsg, proposalAcceptedEvent{Proposal: *pV, Round: r, Period: p})

	// vote in same round p + 1 should also be fine
	pV = helper.MakeRandomProposalValue()
	v = helper.MakeVerifiedVote(t, 0, r, p+1, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: voteVerified,
			Input: message{
				UnauthenticatedVote: v.u(),
				Vote:                v,
			},
		},
	}
	b.AddInOutPair(inMsg, proposalAcceptedEvent{Proposal: *pV, Round: r, Period: p})

	// vote in same round p+ 2 should be filtered
	pV = helper.MakeRandomProposalValue()
	v = helper.MakeVerifiedVote(t, 0, r, p+2, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: voteVerified,
			Input: message{
				UnauthenticatedVote: v.u(),
				Vote:                v,
			},
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// vote in same round p - 2 should be filtered
	pV = helper.MakeRandomProposalValue()
	v = helper.MakeVerifiedVote(t, 0, r, p-2, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: voteVerified,
			Input: message{
				UnauthenticatedVote: v.u(),
				Vote:                v,
			},
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// vote in r + 1 should be filtered unless period 0
	pV = helper.MakeRandomProposalValue()
	v = helper.MakeVerifiedVote(t, 0, r+1, 1, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: voteVerified,
			Input: message{
				UnauthenticatedVote: v.u(),
				Vote:                v,
			},
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	pV = helper.MakeRandomProposalValue()
	v = helper.MakeVerifiedVote(t, 0, r+1, 0, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: voteVerified,
			Input: message{
				UnauthenticatedVote: v.u(),
				Vote:                v,
			},
		},
	}
	b.AddInOutPair(inMsg, proposalAcceptedEvent{Proposal: *pV, Round: r, Period: p})

	// vote > r + 1 should be filtered
	pV = helper.MakeRandomProposalValue()
	v = helper.MakeVerifiedVote(t, 0, r+2, 0, s, *pV)
	inMsg = filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: voteVerified,
			Input: message{
				UnauthenticatedVote: v.u(),
				Vote:                v,
			},
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	res, err := b.Build().Validate(pM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteVerified accidentally filtered")
}

func TestProposalManagerCancelledVoteFiltered(t *testing.T) {
	const r = 100000
	const p = 2
	const s = cert
	_, pM, helper := setupManager(t, r)
	b := testCaseBuilder{}
	currentPlayerState := freshnessData{
		PlayerRound:          r,
		PlayerPeriod:         p,
		PlayerStep:           s,
		PlayerLastConcluding: 0,
	}

	// generate vote in same round same period, should be fine, but lets cancel it
	pV := helper.MakeRandomProposalValue()
	uv := helper.MakeUnauthenticatedVote(t, 0, r, p, s, *pV)
	inMsg := filterableMessageEvent{
		FreshnessData: currentPlayerState,
		messageEvent: messageEvent{
			T: voteVerified,
			Input: message{
				UnauthenticatedVote: uv,
			},
		},
	}
	inMsg.Cancelled = true
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})
	res, err := b.Build().Validate(pM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Cancelled message should have been filtered")
}
