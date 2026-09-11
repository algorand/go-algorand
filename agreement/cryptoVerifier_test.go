// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"math"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
)

var _ = fmt.Printf

func findSenders(l Ledger, Round basics.Round, Period period, Step step, addresses []basics.Address, selections []*crypto.VRFSecrets) []int {
	senders := []int{}
	for i, sender := range addresses {
		m, _ := membership(l, sender, Round, Period, Step)
		cred := committee.MakeCredential(&selections[i].SK, m.Selector)
		if _, err := cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m); err == nil {
			senders = append(senders, i)
		}
	}
	return senders
}

func findSender(l Ledger, Round basics.Round, Period period, Step step, addresses []basics.Address, selections []*crypto.VRFSecrets) int {
	idxs := findSenders(l, Round, Period, Step, addresses, selections)
	if len(idxs) == 0 {
		return -1
	}
	return idxs[0]
}

func makeUnauthenticatedVote(l Ledger, sender basics.Address, selection *crypto.VRFSecrets, voting crypto.OneTimeSigner, Round basics.Round, Period period, Step step, Proposal proposalValue) unauthenticatedVote {
	rv := rawVote{
		Sender:   sender,
		Round:    Round,
		Period:   Period,
		Step:     Step,
		Proposal: Proposal,
	}

	m, _ := membership(l, rv.Sender, rv.Round, rv.Period, rv.Step)
	cred := committee.MakeCredential(&selection.SK, m.Selector)
	ephID := basics.OneTimeIDForRound(rv.Round, voting.KeyDilution(config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution))
	sig := voting.Sign(ephID, rv)

	return unauthenticatedVote{
		R:    rv,
		Sig:  sig,
		Cred: cred,
	}
}
func makeMessage(msgHandle int, tag protocol.Tag, sender basics.Address, l Ledger, selection *crypto.VRFSecrets, voting crypto.OneTimeSigner, Round basics.Round, Period period, Step step) message {
	switch tag {
	case protocol.AgreementVoteTag:
		e := makeRandomBlock(1)
		proposal := proposalValue{
			OriginalPeriod:   Period,
			OriginalProposer: sender,
			BlockDigest:      e.Digest(),
			//EncodingDigest:   proposal.EncodingDigest,
		}

		return message{
			messageHandle:       MessageHandle(msgHandle),
			Tag:                 tag,
			UnauthenticatedVote: makeUnauthenticatedVote(l, sender, selection, voting, Round, Period, Step, proposal),
		}
	case protocol.ProposalPayloadTag:
		e := makeRandomBlock(1)
		payload := unauthenticatedProposal{
			Block: e,
		}
		return message{
			messageHandle:           MessageHandle(msgHandle),
			Tag:                     tag,
			UnauthenticatedProposal: payload,
		}
	default: // protocol.VoteBundleTag
		return message{
			messageHandle: MessageHandle(msgHandle),
			Tag:           tag,
			UnauthenticatedBundle: unauthenticatedBundle{
				Round:    Round,
				Period:   Period,
				Step:     Step,
				Proposal: makeProposalValue(Period, sender),
			},
		}
	}
}
func makeProposalValue(period period, address basics.Address) proposalValue {
	return proposalValue{
		OriginalPeriod:   period,
		OriginalProposer: address,
	}
}

func getSelectorCapacity(tag protocol.Tag) int {
	switch tag {
	case protocol.AgreementVoteTag:
		return voteParallelism
	case protocol.ProposalPayloadTag:
		return proposalParallelism
	default: // protocol.VoteBundleTag
		return bundleParallelism
	}
}

func TestCryptoVerifierBuffers(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Skip("Test is flaky")

	t.Parallel()
	ledger, addresses, selections, votings := readOnlyFixture100()
	ctx := context.Background()

	verifier := makeCryptoVerifier(ledger, testBlockValidator{}, MakeAsyncVoteVerifier(nil), logging.Base())

	msgTypes := []protocol.Tag{protocol.AgreementVoteTag, protocol.ProposalPayloadTag, protocol.VoteBundleTag}

	msgIDs := rand.Perm(20000)
	usedMsgIDs := make(map[MessageHandle]struct{})
	senderIdx := findSender(ledger, basics.Round(300), 0, 0, addresses, selections)
	for _, msgType := range msgTypes {
		assert.False(t, verifier.ChannelFull(msgType))
		// enqueue enough messages to fill up the queues.
		// the 5 multiplier is 2 for the input channel, 2 for the output channel and 1 for the concurrent running threads.
		for i := getSelectorCapacity(msgType) * 5; i > 0; i-- {
			msgID := msgIDs[0]
			msgIDs = msgIDs[1:]
			usedMsgIDs[msgID] = struct{}{}
			switch msgType {
			case protocol.AgreementVoteTag:
				verifier.VerifyVote(ctx, cryptoVoteRequest{message: makeMessage(msgID, msgType, addresses[senderIdx], ledger, selections[senderIdx], votings[senderIdx], 300, 0, 0), Round: ledger.NextRound()})
			case protocol.ProposalPayloadTag:
				verifier.VerifyProposal(ctx, cryptoProposalRequest{message: makeMessage(msgID, msgType, addresses[senderIdx], ledger, selections[senderIdx], votings[senderIdx], 300, 0, 0), Round: ledger.NextRound()})
			case protocol.VoteBundleTag:
				verifier.VerifyBundle(ctx, cryptoBundleRequest{message: makeMessage(msgID, msgType, addresses[senderIdx], ledger, selections[senderIdx], votings[senderIdx], 300, 0, 0), Round: ledger.NextRound()})
			}
		}
		// test to see that queues are full
		assert.Equal(t, len(verifier.Verified(msgType)), getSelectorCapacity(msgType)*2)
		assert.True(t, verifier.ChannelFull(msgType))
	}

	// try to dequeue all the channels
	for _, msgType := range msgTypes {
		for i := getSelectorCapacity(msgType) * 5; i > 0; i-- {
			msg := <-verifier.Verified(msgType)
			_, has := usedMsgIDs[msg.messageHandle]
			assert.True(t, has)
			delete(usedMsgIDs, msg.messageHandle)
		}
		assert.False(t, verifier.ChannelFull(msgType))
		assert.Zero(t, len(verifier.Verified(msgType)))
	}
	assert.Zero(t, len(usedMsgIDs))

	var msgIDMutex deadlock.Mutex
	// perform a high load test
	const lotsOfMessages = 12000
	msgCounters := []int32{0, 0, 0}
	writeTotals := int32(0)
	for writerIdx := 0; writerIdx < 64; writerIdx++ {
		go func(i int) {
			rand.Seed(int64(i))
			for {
				if atomic.AddInt32(&writeTotals, 1) <= lotsOfMessages {
					msgIdx := rand.Int() % len(msgTypes)
					tag := msgTypes[msgIdx]
					atomic.AddInt32(&msgCounters[msgIdx], 1)
					msgIDMutex.Lock()
					msgID := msgIDs[0]
					msgIDs = msgIDs[1:]
					usedMsgIDs[msgID] = struct{}{}
					msgIDMutex.Unlock()

					switch tag {
					case protocol.AgreementVoteTag:
						verifier.VerifyVote(ctx, cryptoVoteRequest{message: makeMessage(msgID, tag, addresses[senderIdx], ledger, selections[senderIdx], votings[senderIdx], 300, 0, 0), Round: ledger.NextRound()})
					case protocol.ProposalPayloadTag:
						verifier.VerifyProposal(ctx, cryptoProposalRequest{message: makeMessage(msgID, tag, addresses[senderIdx], ledger, selections[senderIdx], votings[senderIdx], 300, 0, 0), Round: ledger.NextRound()})
					case protocol.VoteBundleTag:
						verifier.VerifyBundle(ctx, cryptoBundleRequest{message: makeMessage(msgID, tag, addresses[senderIdx], ledger, selections[senderIdx], votings[senderIdx], 300, 0, 0), Round: ledger.NextRound()})
					}
				} else {
					atomic.AddInt32(&writeTotals, -1)
					return
				}
			}
		}(writerIdx)
	}

	verifyMessageHandle := func(msg cryptoResult, ok bool) bool {
		if !ok {
			return false
		}
		msgIDMutex.Lock()
		defer msgIDMutex.Unlock()
		_, has := usedMsgIDs[msg.messageHandle]
		delete(usedMsgIDs, msg.messageHandle)
		return assert.True(t, has)
	}

	readTotals := int32(lotsOfMessages)
	// create multiple readers.
	for readerIdx := 0; readerIdx < 8; readerIdx++ {
		go func() {
			idx := 0
			// read from the channel, until all messages reach
			for atomic.LoadInt32(&readTotals) > 0 {
				select {
				case msg, ok := <-verifier.Verified(msgTypes[0]):
					idx = 0
					if !verifyMessageHandle(msg, ok) {
						return
					}
				case msg, ok := <-verifier.Verified(msgTypes[1]):
					idx = 1
					if !verifyMessageHandle(msg, ok) {
						return
					}
				case msg, ok := <-verifier.Verified(msgTypes[2]):
					idx = 2
					if !verifyMessageHandle(msg, ok) {
						return
					}
				}
				atomic.AddInt32(&msgCounters[idx], -1)
				atomic.AddInt32(&readTotals, -1)
			}
		}()
	}

	// read from the channel, until all messages reach
	for atomic.LoadInt32(&readTotals) > 0 {
		time.Sleep(time.Duration(20) * time.Millisecond)
	}

	// ensure each of the counters reached zero.
	for i := range msgTypes {
		assert.Equal(t, atomic.LoadInt32(&msgCounters[i]), int32(0))
	}

	assert.Zero(t, len(usedMsgIDs))

	verifier.Quit()
}

func BenchmarkCryptoVerifierVoteVertification(b *testing.B) {
	ledger, addresses, selections, votings := readOnlyFixture100()
	ctx := context.Background()

	verifier := makeCryptoVerifier(ledger, testBlockValidator{}, MakeAsyncVoteVerifier(nil), logging.Base())
	c := verifier.Verified(protocol.AgreementVoteTag)

	senderIdx := findSender(ledger, basics.Round(300), 0, 0, addresses, selections)
	request := cryptoVoteRequest{message: makeMessage(0, protocol.AgreementVoteTag, addresses[senderIdx], ledger, selections[senderIdx], votings[senderIdx], 300, 0, 0), Round: ledger.NextRound()}
	b.ResetTimer()
	go func() {
		for n := 0; n < b.N; n++ {
			verifier.VerifyVote(ctx, request)
		}
	}()
	for n := 0; n < b.N; n++ {
		<-c
	}
}

func BenchmarkCryptoVerifierProposalVertification(b *testing.B) {
	ledger, addresses, selections, votings := readOnlyFixture100()

	participations := make([]account.Participation, len(selections))
	for i := range selections {
		participations[i].Parent = addresses[i]
		participations[i].VRF = selections[i]
		participations[i].Voting = votings[i].OneTimeSignatureSecrets
		participations[i].FirstValid = basics.Round(0)
		participations[i].LastValid = basics.Round(1000)
		participations[i].KeyDilution = votings[i].OptionalKeyDilution
	}

	pn := &asyncPseudonode{
		factory:   testBlockFactory{Owner: 0},
		validator: testBlockValidator{},
		keys:      makeRecordingKeyManager(participations),
		ledger:    ledger,
		log:       serviceLogger{logging.Base()},
	}

	Period := period(0)
	pn.loadRoundParticipationKeys(ledger.NextRound())
	participation := pn.participationKeys

	proposals, _ := pn.makeProposals(ledger.NextRound(), Period, participation)

	ctx := context.Background()

	verifier := makeCryptoVerifier(ledger, testBlockValidator{}, MakeAsyncVoteVerifier(nil), logging.Base())
	c := verifier.Verified(protocol.ProposalPayloadTag)
	request := cryptoProposalRequest{
		message: message{
			messageHandle:           MessageHandle(0),
			Tag:                     protocol.ProposalPayloadTag,
			UnauthenticatedProposal: proposals[0].unauthenticatedProposal,
		},
		TaskIndex: 0,
		Round:     ledger.NextRound(),
	}
	b.ResetTimer()
	go func() {
		for n := 0; n < b.N; n++ {
			verifier.VerifyProposal(ctx, request)
		}
	}()
	for n := 0; n < b.N; n++ {
		<-c
	}
}

func BenchmarkCryptoVerifierBundleVertification(b *testing.B) {
	ledger, addresses, selections, votings := readOnlyFixture7000()
	ctx := context.Background()
	verifier := makeCryptoVerifier(ledger, testBlockValidator{}, MakeAsyncVoteVerifier(nil), logging.Base())
	c := verifier.Verified(protocol.VoteBundleTag)

	Step := step(5)
	senders := findSenders(ledger, ledger.NextRound(), 0, Step, addresses, selections)

	request := cryptoBundleRequest{message: makeMessage(0, protocol.VoteBundleTag, addresses[senders[0]], ledger, selections[senders[0]], votings[senders[0]], ledger.NextRound(), 0, Step), Round: ledger.NextRound()}
	for _, senderIdx := range senders {
		uv := makeUnauthenticatedVote(ledger, addresses[senderIdx], selections[senderIdx], votings[senderIdx], request.message.UnauthenticatedBundle.Round, request.message.UnauthenticatedBundle.Period, Step, request.message.UnauthenticatedBundle.Proposal)
		v, err := uv.verify(ledger)
		if err != nil {
			b.Errorf("unable to verify created vote : %+v", err)
			return
		}
		va := voteAuthenticator{
			Sender: uv.R.Sender,
			Cred:   uv.Cred,
			Sig:    v.Sig,
		}
		request.message.UnauthenticatedBundle.Votes = append(request.message.UnauthenticatedBundle.Votes, va)

	}

	b.ResetTimer()
	go func() {
		for n := 0; n < b.N; n++ {
			verifier.VerifyBundle(ctx, request)
		}
	}()
	for n := 0; n < b.N; n++ {
		<-c
	}
}

// TestCryptoVerifierVerificationErrs tests to see that the cryptoVerifier.VerifyVote returns an error in the vote response
// when being unable to enqueue a vote.
func TestCryptoVerifierVerificationErrs(t *testing.T) {
	partitiontest.PartitionTest(t)

	mainPool := execpool.MakePool(t)
	defer mainPool.Shutdown()

	voteVerifier := MakeAsyncVoteVerifier(&expiredExecPool{mainPool})
	defer voteVerifier.Quit()

	cryptoVerifier := makeCryptoVerifier(nil, nil, voteVerifier, logging.TestingLog(t))
	defer cryptoVerifier.Quit()

	cryptoVerifier.VerifyVote(context.Background(), cryptoVoteRequest{message: message{Tag: protocol.AgreementVoteTag}, Round: basics.Round(8), TaskIndex: uint64(14)})
	// read the failed response from VerifiedVotes:
	votesout := cryptoVerifier.VerifiedVotes()
	voteResponse := <-votesout
	require.Equal(t, context.Canceled, voteResponse.err)
	require.True(t, voteResponse.cancelled)
	require.Equal(t, uint64(14), voteResponse.index)
}

// Bundle admission must not let unauthenticated periods cancel other work or
// allocate an entry for every distinct period. Exercise VerifyBundle itself,
// draining its input synchronously so the checks do not depend on scheduling.
func TestCryptoVerifierBundleContextIsolation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, bundleStep := range []step{soft, next, cert} {
		t.Run(fmt.Sprint(bundleStep), func(t *testing.T) {
			c := &poolCryptoVerifier{
				proposalContexts: makePendingRequestsContext(),
				bundles:          bundleChanPair{in: make(chan cryptoBundleRequest, 1)},
			}
			const rnd, per = 10, 7
			voteCtx := c.proposalContexts.addVote(cryptoVoteRequest{Round: rnd, Period: per})
			payloadCtx := c.proposalContexts.addProposal(cryptoProposalRequest{Round: rnd, Period: per})
			pinnedCtx := c.proposalContexts.addProposal(cryptoProposalRequest{Round: rnd, Pinned: true})
			defer c.proposalContexts[rnd].cancel()

			var bundleCtx context.Context
			for _, future := range []period{per + 3, 1000, 999, 998, math.MaxUint64, math.MaxUint64 - 1} {
				ub := unauthenticatedBundle{Round: rnd, Period: future, Step: bundleStep}
				if future%2 == 0 {
					// Nonempty bundles with invalid authenticators have the same
					// context effects as empty bundles before verification.
					ub.Votes = []voteAuthenticator{{}}
				}
				require.NoError(t, bundleFresh(freshnessData{PlayerRound: rnd, PlayerPeriod: per}, ub))
				c.VerifyBundle(context.Background(), cryptoBundleRequest{
					message: message{Tag: protocol.VoteBundleTag, UnauthenticatedBundle: ub},
					Round:   rnd,
				})
				request := <-c.bundles.in
				require.NoError(t, voteCtx.Err(), "bundle cancelled an honest vote")
				require.NoError(t, payloadCtx.Err(), "bundle cancelled an honest payload")
				require.NoError(t, pinnedCtx.Err(), "bundle cancelled a pinned payload")
				require.NoError(t, request.ctx.Err())
				if bundleCtx == nil {
					bundleCtx = request.ctx
				} else {
					require.Same(t, bundleCtx, request.ctx, "bundle periods must share a context")
				}
				require.Len(t, c.proposalContexts, 1)
				require.Len(t, c.proposalContexts[rnd].periods, 3, "one period, one pinned payload, and one bundle context")
			}

			// Legitimate period progress still cancels obsolete ordinary work,
			// while bundles and pinned payloads survive until round cleanup.
			c.proposalContexts.clearStaleContexts(rnd, per+3, false, false)
			require.ErrorIs(t, voteCtx.Err(), context.Canceled)
			require.ErrorIs(t, payloadCtx.Err(), context.Canceled)
			require.NoError(t, pinnedCtx.Err())
			require.NoError(t, bundleCtx.Err())
			c.proposalContexts.clearStaleContexts(rnd+1, 0, false, false)
			require.NoError(t, bundleCtx.Err())
			c.proposalContexts.clearStaleContexts(rnd+2, 0, false, false)
			require.ErrorIs(t, bundleCtx.Err(), context.Canceled)
			require.ErrorIs(t, pinnedCtx.Err(), context.Canceled)
			require.Empty(t, c.proposalContexts)
		})
	}
}

func TestCryptoVerifierBundleContextBound(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	c := &poolCryptoVerifier{
		proposalContexts: makePendingRequestsContext(),
		bundles:          bundleChanPair{in: make(chan cryptoBundleRequest, 1)},
	}
	const rnd = 10
	defer func() { c.proposalContexts[rnd].cancel() }()
	for future := period(1000); future > 900; future-- {
		ub := unauthenticatedBundle{Round: rnd, Period: future, Step: soft}
		c.VerifyBundle(context.Background(), cryptoBundleRequest{
			message: message{Tag: protocol.VoteBundleTag, UnauthenticatedBundle: ub},
			Round:   rnd,
		})
		<-c.bundles.in
		require.Len(t, c.proposalContexts, 1)
		require.Len(t, c.proposalContexts[rnd].periods, 1, "bundle contexts grew with unauthenticated periods")
	}
}

// Bundle admission alone must collect old round contexts; cleanup must not
// depend on a vote or payload request arriving first.
func TestCryptoVerifierBundleContextCleanupByRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	c := &poolCryptoVerifier{
		proposalContexts: makePendingRequestsContext(),
		bundles:          bundleChanPair{in: make(chan cryptoBundleRequest, 1)},
	}
	t.Cleanup(func() {
		for _, roundCtx := range c.proposalContexts {
			roundCtx.cancel()
		}
	})

	verifyBundle := func(r round) context.Context {
		t.Helper()
		ub := unauthenticatedBundle{Round: r, Period: 1000, Step: soft}
		require.NoError(t, bundleFresh(freshnessData{PlayerRound: r}, ub))
		c.VerifyBundle(context.Background(), cryptoBundleRequest{
			message: message{Tag: protocol.VoteBundleTag, UnauthenticatedBundle: ub},
			Round:   r,
		})
		request := <-c.bundles.in
		require.NoError(t, request.ctx.Err())
		return request.ctx
	}

	const rnd round = 10
	firstCtx := verifyBundle(rnd)
	nextCtx := verifyBundle(rnd + 1)
	require.NoError(t, firstCtx.Err(), "previous-round work must remain live")
	require.Len(t, c.proposalContexts, 2)

	currentCtx := verifyBundle(rnd + 2)
	require.ErrorIs(t, firstCtx.Err(), context.Canceled)
	require.NotContains(t, c.proposalContexts, rnd)
	require.NoError(t, nextCtx.Err())
	require.NoError(t, currentCtx.Err())
	require.Len(t, c.proposalContexts, 2, "bundles must collect old round contexts without votes or payloads")
}

func TestCryptoVerifierFutureBundleVerification(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ledger, addresses, selections, signers := readOnlyFixture100()
	rnd := ledger.NextRound()
	const future = 1000
	var votes []vote
	for i, address := range addresses {
		uv, err := makeVote(rawVote{Sender: address, Round: rnd, Period: future, Step: next, Proposal: bottom}, signers[i], selections[i], ledger)
		require.NoError(t, err)
		v, err := uv.verify(ledger)
		if err == nil {
			votes = append(votes, v)
		}
	}
	ub := makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], bottom, votes, nil)
	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	c := makeCryptoVerifier(ledger, testBlockValidator{}, avv, logging.TestingLog(t)).(*poolCryptoVerifier)
	defer c.Quit()
	payloadCtx := c.proposalContexts.addProposal(cryptoProposalRequest{Round: rnd, Period: 0})
	defer c.proposalContexts[rnd].cancel()

	verify := func(b unauthenticatedBundle) cryptoResult {
		t.Helper()
		require.NoError(t, bundleFresh(freshnessData{PlayerRound: rnd}, b))
		c.VerifyBundle(context.Background(), cryptoBundleRequest{
			message: message{Tag: protocol.VoteBundleTag, UnauthenticatedBundle: b},
			Round:   rnd,
		})
		select {
		case result := <-c.Verified(protocol.VoteBundleTag):
			require.False(t, result.Cancelled)
			require.NoError(t, payloadCtx.Err())
			return result
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for bundle verification")
			return cryptoResult{}
		}
	}

	// Invalid future bundles must still be rejected, without cancelling payloads
	// or retaining a new context for each completed request.
	for per := period(future + 10); per > future; per-- {
		invalid := ub
		invalid.Period = per // signatures were made for a different period
		require.NotNil(t, verify(invalid).Err)
		require.Len(t, c.proposalContexts[rnd].periods, 2)
	}

	// A genuine future-period quorum must remain eligible for fast-forwarding.
	result := verify(ub)
	require.Nil(t, result.Err)
	require.Equal(t, ub, result.Bundle.U)
}
