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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/timers"
   "github.com/algorand/go-algorand/testPartitioning"
)

const fastTimeoutChTime = 2

type demuxTester struct {
	*testing.T
	currentUsecase *demuxTestUsecase
	testIdx        int
}

type testChanState struct {
	eventCount uint
	closed     bool
}
type demuxTestUsecase struct {
	// input state
	queue               []testChanState
	rawVotes            testChanState
	rawProposals        testChanState
	rawBundles          testChanState
	compoundProposals   bool
	quit                bool
	voteChannelFull     bool
	proposalChannelFull bool
	bundleChannelFull   bool
	ledgerRoundReached  bool // <-s.Ledger.Wait(nextRound):
	deadlineReached     bool
	verifiedVote        testChanState
	verifiedProposal    testChanState
	verifiedBundle      testChanState
	// expected output
	e  event
	ok bool
}

var demuxTestUsecases = []demuxTestUsecase{
	{
		queue:               []testChanState{{eventCount: 1, closed: false}},
		rawVotes:            testChanState{eventCount: 1, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{Err: makeSerErrStr("QueueEvent-0-0")},
		ok:                  true,
	},
	{
		queue:               []testChanState{{eventCount: 0, closed: true}, {eventCount: 1, closed: true}},
		rawVotes:            testChanState{eventCount: 1, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{Err: makeSerErrStr("QueueEvent-1-0")},
		ok:                  true,
	},
	{
		queue:               []testChanState{{eventCount: 0, closed: false}},
		rawVotes:            testChanState{eventCount: 1, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                true,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   emptyEvent{},
		ok:                  false,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 1, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{T: payloadPresent},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 1, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{T: bundlePresent},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 1, closed: false},
		rawProposals:        testChanState{eventCount: 1, closed: false},
		rawBundles:          testChanState{eventCount: 1, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     true,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{T: bundlePresent},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 1, closed: false},
		rawProposals:        testChanState{eventCount: 1, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: true,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{T: votePresent},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 1, closed: false},
		rawBundles:          testChanState{eventCount: 1, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: true,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{T: bundlePresent},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 1, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   true,
		ledgerRoundReached:  true,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   roundInterruptionEvent{},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 1, closed: false},
		rawProposals:        testChanState{eventCount: 1, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                true,
		voteChannelFull:     true,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   emptyEvent{},
		ok:                  false,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 1, closed: false},
		rawProposals:        testChanState{eventCount: 1, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     true,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  true,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   roundInterruptionEvent{},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 1, closed: false},
		rawProposals:        testChanState{eventCount: 1, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     true,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     true,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   timeoutEvent{T: timeout},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 1, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{T: voteVerified, Err: makeSerErrStr("Verified-AV-{test_index}-0")},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 1, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{T: payloadVerified, Err: makeSerErrStr("Verified-PP-{test_index}-0")},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 1, closed: false},
		e:                   messageEvent{T: bundleVerified, Err: makeSerErrStr("Verified-VB-{test_index}-0")},
		ok:                  true,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: true},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   emptyEvent{},
		ok:                  false,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: true},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   emptyEvent{},
		ok:                  false,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 0, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: true},
		compoundProposals:   false,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   emptyEvent{},
		ok:                  false,
	},
	{
		queue:               []testChanState{},
		rawVotes:            testChanState{eventCount: 0, closed: false},
		rawProposals:        testChanState{eventCount: 1, closed: false},
		rawBundles:          testChanState{eventCount: 0, closed: false},
		compoundProposals:   true,
		quit:                false,
		voteChannelFull:     false,
		proposalChannelFull: false,
		bundleChannelFull:   false,
		ledgerRoundReached:  false,
		deadlineReached:     false,
		verifiedVote:        testChanState{eventCount: 0, closed: false},
		verifiedProposal:    testChanState{eventCount: 0, closed: false},
		verifiedBundle:      testChanState{eventCount: 0, closed: false},
		e:                   messageEvent{T: votePresent},
		ok:                  true,
	},
}

func TestDemuxNext(t *testing.T) {
   testPartitioning.PartitionTest(t)

	dt := &demuxTester{T: t}
	dt.Test()
}

// implement timers.Clock
func (t *demuxTester) Zero() timers.Clock {
	// we don't care about this function in this test.
	return t
}

// implement timers.Clock
func (t *demuxTester) TimeoutAt(delta time.Duration) <-chan time.Time {
	if delta == fastTimeoutChTime {
		return nil
	}

	c := make(chan time.Time, 2)
	if t.currentUsecase.deadlineReached {
		// return a closed channel.
		c <- time.Now()
		close(c)
		return c
	}
	return c
}

// implement timers.Clock
func (t *demuxTester) Encode() []byte {
	// we don't care about this function in this test.
	return []byte{}
}

// implement timers.Clock
func (t *demuxTester) Decode([]byte) (timers.Clock, error) {
	// we don't care about this function in this test.
	return t, nil
}

// implement Ledger
func (t *demuxTester) NextRound() basics.Round {
	return 1234
}

// implement Ledger
func (t *demuxTester) Wait(basics.Round) chan struct{} {
	c := make(chan struct{})
	if t.currentUsecase.ledgerRoundReached {
		// return a closed channel.
		close(c)
		return c
	}
	return c
}

// implement Ledger
func (t *demuxTester) Seed(basics.Round) (committee.Seed, error) {
	// we don't care about this function in this test.
	return committee.Seed{}, nil
}

// implement Ledger
func (t *demuxTester) LookupDigest(basics.Round) (crypto.Digest, error) {
	// we don't care about this function in this test.
	return crypto.Digest{}, nil
}

// implement Ledger
func (t *demuxTester) Lookup(basics.Round, basics.Address) (basics.AccountData, error) {
	// we don't care about this function in this test.
	return basics.AccountData{}, nil
}

// implement Ledger
func (t *demuxTester) Circulation(basics.Round) (basics.MicroAlgos, error) {
	// we don't care about this function in this test.
	return basics.MicroAlgos{}, nil
}

// implement Ledger
func (t *demuxTester) ConsensusParams(basics.Round) (config.ConsensusParams, error) {
	// we don't care about this function in this test.
	return config.Consensus[protocol.ConsensusCurrentVersion], nil
}

// implement Ledger
func (t *demuxTester) ConsensusVersion(basics.Round) (protocol.ConsensusVersion, error) {
	// we don't care about this function in this test.
	return protocol.ConsensusCurrentVersion, nil
}

// implement Ledger
func (t *demuxTester) EnsureBlock(bookkeeping.Block, Certificate) {
	// we don't care about this function in this test.
}

// implement Ledger
func (t *demuxTester) EnsureValidatedBlock(ValidatedBlock, Certificate) {
	// we don't care about this function in this test.
}

// implement Ledger
func (t *demuxTester) EnsureDigest(Certificate, *AsyncVoteVerifier) {
	// we don't care about this function in this test.
}

// implement cryptoVerifier
func (t *demuxTester) VerifyProposal(ctx context.Context, request cryptoProposalRequest) {
	// we don't care about this function in this test.
}

// implement cryptoVerifier
func (t *demuxTester) VerifyBundle(ctx context.Context, request cryptoBundleRequest) {
	// we don't care about this function in this test.
}

// implement cryptoVerifier
func (t *demuxTester) VerifyVote(ctx context.Context, request cryptoVoteRequest) {
	// we don't care about this function in this test.
}

// implement cryptoVerifier
func (t *demuxTester) Verified(tag protocol.Tag) <-chan cryptoResult {
	var cs testChanState
	switch tag {
	case protocol.ProposalPayloadTag:
		cs = t.currentUsecase.verifiedProposal
	case protocol.VoteBundleTag:
		cs = t.currentUsecase.verifiedBundle
	default:
		return nil
	}

	c := make(chan cryptoResult, cs.eventCount+1)
	for i := uint(0); i < cs.eventCount; i++ {
		c <- cryptoResult{Err: makeSerErrf("Verified-%s-%d-%d", tag, t.testIdx, i)}
	}

	if cs.closed {
		close(c)
	}

	return c
}

// implement cryptoVerifier
func (t *demuxTester) VerifiedVotes() <-chan asyncVerifyVoteResponse {
	var cs testChanState
	cs = t.currentUsecase.verifiedVote

	c := make(chan asyncVerifyVoteResponse, cs.eventCount+1)
	for i := uint(0); i < cs.eventCount; i++ {
		c <- asyncVerifyVoteResponse{err: makeSerErrf("Verified-%s-%d-%d", protocol.AgreementVoteTag, t.testIdx, i)}
	}

	if cs.closed {
		close(c)
	}

	return c
}

// implement cryptoVerifier
func (t *demuxTester) ChannelFull(tag protocol.Tag) bool {
	switch tag {
	case protocol.AgreementVoteTag:
		return t.currentUsecase.voteChannelFull
	case protocol.ProposalPayloadTag:
		return t.currentUsecase.proposalChannelFull
	case protocol.VoteBundleTag:
		return t.currentUsecase.bundleChannelFull
	default:
		return false
	}
}

// implement cryptoVerifier
func (t *demuxTester) Quit() {
	// not used in this test.
}
func (t *demuxTester) Test() {
	for testIdx, usecase := range demuxTestUsecases {
		t.testIdx = testIdx
		t.TestUsecase(usecase)
	}
}

func (t *demuxTester) makeRawChannel(tag protocol.Tag, cs testChanState, compound bool) <-chan message {
	c := make(chan message, cs.eventCount)
	for i := uint(0); i < cs.eventCount; i++ {
		if !compound {
			msg := message{Tag: tag}
			c <- msg
		} else {
			msg := message{Tag: tag}
			msg.CompoundMessage.Vote = unauthenticatedVote{R: rawVote{Step: step(3 + i)}}
			c <- msg
		}

	}

	if cs.closed {
		close(c)
	}
	return c
}

// Uint64 provides a stub for the randomness.
func (t *demuxTester) Uint64() uint64 {
	return uint64(5)
}

func (t *demuxTester) makeQueueEvent(evt testChanState) <-chan externalEvent {
	c := make(chan externalEvent, evt.eventCount)
	for i := uint(0); i < evt.eventCount; i++ {
		c <- messageEvent{Err: makeSerErrf("QueueEvent-%d-%d", t.testIdx, i)}
	}

	if evt.closed {
		close(c)
	}
	return c
}

func (t *demuxTester) TestUsecase(testcase demuxTestUsecase) bool {
	t.currentUsecase = &testcase
	defer func() {
		t.currentUsecase = nil
	}()

	dmx := &demux{}

	dmx.crypto = t
	dmx.ledger = t
	dmx.rawVotes = t.makeRawChannel(protocol.AgreementVoteTag, testcase.rawVotes, false)
	dmx.rawProposals = t.makeRawChannel(protocol.ProposalPayloadTag, testcase.rawProposals, testcase.compoundProposals)
	dmx.rawBundles = t.makeRawChannel(protocol.VoteBundleTag, testcase.rawBundles, false)

	// initiliaze the queue.
	dmx.queue = make([]<-chan externalEvent, len(testcase.queue))
	for i, qEvt := range testcase.queue {
		dmx.queue[i] = t.makeQueueEvent(qEvt)
	}

	s := &Service{}
	s.quit = make(chan struct{})
	s.Clock = t
	s.Ledger = t
	s.RandomSource = t
	s.log = serviceLogger{logging.Base()}
	if testcase.quit {
		close(s.quit)
	}

	e, ok := dmx.next(s, time.Second, fastTimeoutChTime, 300)

	if !assert.Equal(t, testcase.ok, ok) {
		return false
	}

	if !assert.Equalf(t, strings.Replace(testcase.e.String(), "{test_index}", fmt.Sprintf("%d", t.testIdx), 1), e.String(), "Test case %d failed.", t.testIdx+1) {
		return false
	}

	if !assert.Equal(t, testcase.e.t(), e.t()) {
		return false
	}

	return true
}
