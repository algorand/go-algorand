// Copyright (C) 2019-2025 Algorand, Inc.
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
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
)

// The serializedPseudonode is the trivial implementation for the pseudonode interface
// that avoids creating goroutines or any "advanced machinery" so that we have a good testing reference
// for the asyncPseudonode
type serializedPseudonode struct {
	asyncPseudonode
}

func drainChannel(ch <-chan externalEvent) []messageEvent {
	events := []messageEvent{}
	for ev := range ch {
		events = append(events, ev.(messageEvent))
	}
	return events
}

func compareRawVote(t *testing.T, r1, r2 rawVote) bool {
	if !assert.Equal(t, r1.Sender, r2.Sender) {
		return false
	}
	if !assert.Equal(t, r1.Round, r2.Round) {
		return false
	}
	if !assert.Equal(t, r1.Period, r2.Period) {
		return false
	}
	if !assert.Equal(t, r1.Step, r2.Step) {
		return false
	}
	if !assert.Equal(t, r1.Proposal.OriginalPeriod, r2.Proposal.OriginalPeriod) {
		return false
	}
	if !assert.Equal(t, r1.Proposal.OriginalProposer, r2.Proposal.OriginalProposer) {
		return false
	}
	return true
}

func compareUnauthenticatedProposal(t *testing.T, r1, r2 unauthenticatedProposal) bool {
	return assert.Equal(t, r1.Block, r2.Block)
}

func compareEventChannels(t *testing.T, ch1, ch2 <-chan externalEvent) bool {
	events1 := drainChannel(ch1)
	events2 := drainChannel(ch2)
	assert.Equal(t, len(events1), len(events2))
	for i, ev1 := range events1 {
		if !assert.Equal(t, ev1.T, events2[i].T) {
			return false
		}
		if !assert.Equal(t, ev1.Err, events2[i].Err) {
			return false
		}
		switch ev1.Input.Tag {
		case protocol.AgreementVoteTag:
			if ev1.Err == nil {
				uo := ev1.Input.Vote
				v2 := events2[i].Input.Vote
				if !compareRawVote(t, uo.R, v2.R) {
					return false
				}
			} else {
				uo := ev1.Input.UnauthenticatedVote
				uv2 := events2[i].Input.UnauthenticatedVote
				if !compareRawVote(t, uo.R, uv2.R) {
					return false
				}
			}
		case protocol.ProposalPayloadTag:
			if ev1.Err == nil {
				uo := ev1.Input.Proposal
				p2 := events2[i].Input.Proposal
				if !assert.Equal(t, uo.Block, p2.Block) {
					return false
				}
				if !compareUnauthenticatedProposal(t, uo.u(), p2.u()) {
					return false
				}
				if !assert.Equal(t, uo.Digest(), p2.Digest()) {
					return false
				}
			} else {
				uo := ev1.Input.UnauthenticatedProposal
				up2 := events2[i].Input.UnauthenticatedProposal
				if !compareUnauthenticatedProposal(t, uo, up2) {
					return false
				}
				if !assert.Equal(t, protocol.Encode(&uo), protocol.Encode(&up2)) {
					return false
				}
				if !assert.Equal(t, uo.Digest(), up2.Digest()) {
					return false
				}
			}
		default:
			assert.NoError(t, fmt.Errorf("Unexpected tag '%v' encountered", ev1.Input.Tag))
		}
	}
	return true
}

func TestPseudonode(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	// generate a nice, fixed hash.
	rootSeed := sha256.Sum256([]byte(t.Name()))
	accounts, balances := createTestAccountsAndBalances(t, 10, rootSeed[:])
	ledger := makeTestLedger(balances)

	sLogger := serviceLogger{logging.NewLogger()}
	sLogger.SetLevel(logging.Warn)

	keyManager := makeRecordingKeyManager(accounts)
	pb := makePseudonode(pseudonodeParams{
		factory:      testBlockFactory{Owner: 0},
		validator:    testBlockValidator{},
		keys:         keyManager,
		ledger:       ledger,
		voteVerifier: MakeAsyncVoteVerifier(nil),
		log:          sLogger,
		monitor:      nil,
	})
	defer pb.Quit()
	spn := makeSerializedPseudonode(testBlockFactory{Owner: 0}, testBlockValidator{}, keyManager, ledger)
	defer spn.Quit()

	startRound := ledger.NextRound()

	channels := make([]<-chan externalEvent, 0)
	var ch <-chan externalEvent
	var err error
	for i := 0; i < pseudonodeVerificationBacklog*2; i++ {
		ch, err = pb.MakeProposals(context.Background(), startRound, period(i))
		if err != nil {
			assert.Subset(t, []int{pseudonodeVerificationBacklog, pseudonodeVerificationBacklog + 1}, []int{i})
			break
		}
		channels = append(channels, ch)
	}
	assert.Error(t, err, "MakeProposals did not returned an error when being overflowed with requests")

	persist := make(chan error)
	close(persist)
	for i := 0; i < pseudonodeVerificationBacklog*2; i++ {
		ch, err = pb.MakeVotes(context.Background(), startRound, period(i), step(i%5), makeProposalValue(period(i), accounts[0].Address()), persist)
		if err != nil {
			assert.Subset(t, []int{pseudonodeVerificationBacklog, pseudonodeVerificationBacklog + 1}, []int{i})
			break
		}
		channels = append(channels, ch)
	}
	assert.Error(t, err, "MakeVotes did not returned an error when being overflowed with requests")

	// drain output channels.
	for _, ch := range channels {
		drainChannel(ch)
	}

	// issue a single make proposal request.
	ch, err = pb.MakeProposals(context.Background(), startRound, period(3))
	assert.NoError(t, err, "MakeProposals failed")
	events := make(map[eventType][]messageEvent)
	events[voteVerified] = []messageEvent{}
	events[payloadVerified] = []messageEvent{}
	for {
		ev, ok := <-ch
		if !ok {
			break
		}
		messageEvent, typeOk := ev.(messageEvent)
		assert.True(t, true, typeOk)
		events[ev.t()] = append(events[ev.t()], messageEvent)
	}
	assert.Subset(t, []int{2, 3, 4, 5, 6, 7, 8, 9, 10}, []int{len(events[voteVerified])})
	assert.Subset(t, []int{2, 3, 4, 5, 6, 7, 8, 9, 10}, []int{len(events[payloadVerified])})

	// issue a single make votes request.
	ch, err = pb.MakeVotes(context.Background(), startRound, period(1), step(2), makeProposalValue(period(1), accounts[0].Address()), persist)
	assert.NoError(t, err, "MakeVotes failed")
	events = make(map[eventType][]messageEvent)
	events[voteVerified] = []messageEvent{}
	events[payloadVerified] = []messageEvent{}
	for {
		ev, ok := <-ch
		if !ok {
			break
		}
		messageEvent, typeOk := ev.(messageEvent)
		assert.True(t, true, typeOk)
		// Verify votes are recorded - everyone is voting and proposing blocks.
		keyManager.ValidateVoteRound(t, messageEvent.Input.Vote.R.Sender, startRound)
		events[messageEvent.t()] = append(events[messageEvent.t()], messageEvent)
	}
	assert.Subset(t, []int{5, 6, 7, 8, 9, 10}, []int{len(events[voteVerified])})
	assert.Equal(t, 0, len(events[payloadVerified]))

	// compare the output of the serialized pseudo node to the queued version.
	for p := 0; p < 3; p++ {
		for ch1src := 0; ch1src < 2; ch1src++ {
			var err1 error
			var ch1 <-chan externalEvent
			if ch1src == 0 {
				ch1, err1 = pb.MakeProposals(context.Background(), startRound, period(p))
			} else {
				ch1, err1 = spn.MakeProposals(context.Background(), startRound, period(p))
			}

			assert.NoError(t, err1, "MakeProposals failed")
			ch2, err2 := spn.MakeProposals(context.Background(), startRound, period(p))
			assert.NoError(t, err2, "MakeProposals failed")
			if !compareEventChannels(t, ch1, ch2) {
				return
			}
		}
	}

	for a := 0; a < 2; a++ {
		for s := 0; s < 3; s++ {
			for p := 0; p < 3; p++ {
				for ch1src := 0; ch1src < 2; ch1src++ {
					var err1 error
					var ch1 <-chan externalEvent
					if ch1src == 0 {
						ch1, err1 = pb.MakeVotes(context.Background(), startRound, period(p), step(s), makeProposalValue(period(p), accounts[a].Address()), persist)
					} else {
						ch1, err1 = spn.MakeVotes(context.Background(), startRound, period(p), step(s), makeProposalValue(period(p), accounts[a].Address()), persist)
					}
					assert.NoError(t, err1, "MakeVotes failed")
					ch2, err2 := spn.MakeVotes(context.Background(), startRound, period(p), step(s), makeProposalValue(period(p), accounts[a].Address()), persist)
					assert.NoError(t, err2, "MakeVotes failed")
					if !compareEventChannels(t, ch1, ch2) {
						return
					}
				}
			}
		}
	}
}

func makeSerializedPseudonode(factory BlockFactory, validator BlockValidator, keys KeyManager, ledger Ledger) pseudonode {
	return serializedPseudonode{
		asyncPseudonode: asyncPseudonode{
			factory:   factory,
			validator: validator,
			keys:      keys,
			ledger:    ledger,
			log:       serviceLogger{logging.Base()},
		},
	}
}

func (n serializedPseudonode) MakeProposals(ctx context.Context, r round, p period) (outChan <-chan externalEvent, err error) {
	verifier := makeCryptoVerifier(n.ledger, n.validator, MakeAsyncVoteVerifier(nil), n.log)
	defer verifier.Quit()

	n.loadRoundParticipationKeys(n.ledger.NextRound())
	participation := n.participationKeys

	proposals, votes := n.makeProposals(r, p, participation)

	out := make(chan externalEvent, len(proposals)+len(votes))
	defer close(out)
	outChan = out

	verifiedVotes := make(verifiedCryptoResults, len(votes))
	verifiedProposals := make([]cryptoResult, len(proposals))

	for i, vote := range votes {
		verifier.VerifyVote(ctx, cryptoVoteRequest{message: message{Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vote}})
		select {
		case cryptoResult, ok := <-verifier.VerifiedVotes():
			if !ok {
				return nil, errPseudonodeVerifierClosedChannel
			}
			verifiedVotes[i] = cryptoResult
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	for i, proposal := range proposals {
		verifier.VerifyProposal(ctx, cryptoProposalRequest{message: message{Tag: protocol.ProposalPayloadTag, UnauthenticatedProposal: proposal.u()}, Round: r})
		select {
		case cryptoResult, ok := <-verifier.Verified(protocol.ProposalPayloadTag):
			if !ok {
				return nil, errPseudonodeVerifierClosedChannel
			}
			verifiedProposals[i] = cryptoResult
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	for i := 0; i < len(verifiedVotes); i++ {
		if verifiedVotes[i].err == nil {
			out <- messageEvent{T: voteVerified, Input: verifiedVotes[i].message}
		}
	}

	for i := 0; i < len(verifiedProposals); i++ {
		if verifiedVotes[i].err == nil {
			out <- messageEvent{T: payloadVerified, Input: verifiedProposals[i].message}
		}
	}

	return
}

func (n serializedPseudonode) MakeVotes(ctx context.Context, r round, p period, s step, prop proposalValue, persistStateDone chan error) (outChan chan externalEvent, err error) {
	verifier := makeCryptoVerifier(n.ledger, n.validator, MakeAsyncVoteVerifier(nil), n.log)
	defer verifier.Quit()

	n.loadRoundParticipationKeys(r)
	participation := n.participationKeys

	votes := n.makeVotes(r, p, s, prop, participation)

	out := make(chan externalEvent, len(votes))
	defer close(out)
	outChan = out

	verifiedVotes := make(verifiedCryptoResults, len(votes))

	for i, vote := range votes {
		verifier.VerifyVote(ctx, cryptoVoteRequest{message: message{Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vote}})
		select {
		case cryptoResult, ok := <-verifier.VerifiedVotes():
			if !ok {
				return nil, errPseudonodeVerifierClosedChannel
			}
			verifiedVotes[i] = cryptoResult
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	<-persistStateDone

	for i := 0; i < len(verifiedVotes); i++ {
		if verifiedVotes[i].err == nil {
			out <- messageEvent{T: voteVerified, Input: verifiedVotes[i].message}
		}
	}

	return
}

func (n serializedPseudonode) Quit() {
	// nothing to do ! this serializedPseudonode is so simplified that no destructor is needed.
}

type KeyManagerProxy struct {
	target func(basics.Round, basics.Round) []account.ParticipationRecordForRound
}

func (k *KeyManagerProxy) VotingKeys(votingRound, balanceRound basics.Round) []account.ParticipationRecordForRound {
	return k.target(votingRound, balanceRound)
}

func (k *KeyManagerProxy) Record(account basics.Address, round basics.Round, action account.ParticipationAction) {
}

func TestPseudonodeLoadingOfParticipationKeys(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	// generate a nice, fixed hash.
	rootSeed := sha256.Sum256([]byte(t.Name()))
	accounts, balances := createTestAccountsAndBalances(t, 10, rootSeed[:])
	ledger := makeTestLedger(balances)

	sLogger := serviceLogger{logging.NewLogger()}
	sLogger.SetLevel(logging.Warn)

	keyManager := makeRecordingKeyManager(accounts)
	pb := makePseudonode(pseudonodeParams{
		factory:      testBlockFactory{Owner: 0},
		validator:    testBlockValidator{},
		keys:         keyManager,
		ledger:       ledger,
		voteVerifier: MakeAsyncVoteVerifier(nil),
		log:          sLogger,
		monitor:      nil,
	}).(asyncPseudonode)
	// verify start condition -
	require.Zero(t, pb.participationKeysRound)
	require.Empty(t, pb.participationKeys)

	// check after round 1
	pb.loadRoundParticipationKeys(basics.Round(1))
	require.Equal(t, basics.Round(1), pb.participationKeysRound)
	require.NotEmpty(t, pb.participationKeys)

	// check the participationKeys retain their prev valud after a call to loadRoundParticipationKeys with 1.
	pb.participationKeys = nil
	pb.loadRoundParticipationKeys(basics.Round(1))
	require.Equal(t, basics.Round(1), pb.participationKeysRound)
	require.Nil(t, pb.participationKeys)

	// check that it's being updated when asked with a different round number.
	returnedPartKeys := pb.loadRoundParticipationKeys(basics.Round(2))
	require.Equal(t, basics.Round(2), pb.participationKeysRound)
	require.NotEmpty(t, pb.participationKeys)
	require.Equal(t, pb.participationKeys, returnedPartKeys)

	// test to see that loadRoundParticipationKeys is calling VotingKeys with the correct parameters.
	keyManagerProxy := &KeyManagerProxy{}
	pb.keys = keyManagerProxy
	cparams, _ := ledger.ConsensusParams(0)
	for rnd := basics.Round(3); rnd < 1000; rnd += 43 {
		keyManagerProxy.target = func(votingRound, balanceRnd basics.Round) []account.ParticipationRecordForRound {
			require.Equal(t, rnd, votingRound)
			require.Equal(t, BalanceRound(rnd, cparams), balanceRnd)
			return keyManager.VotingKeys(votingRound, balanceRnd)
		}
		pb.loadRoundParticipationKeys(basics.Round(rnd))
	}
}

type substrServiceLogger struct {
	logging.Logger
	lookupStrings  []string
	instancesFound []int
}

func (ssl *substrServiceLogger) Infof(s string, args ...interface{}) {
	for i, str := range ssl.lookupStrings {
		if strings.Contains(s, str) {
			ssl.instancesFound[i]++
			return
		}
	}
}

// TestPseudonodeNonEnqueuedTasks test to see that in the case where we cannot enqueue the verification task to the backlog, we won't be waiting forever - instead,
// we would generate a warning message and keep going.
func TestPseudonodeNonEnqueuedTasks(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	// generate a nice, fixed hash.
	rootSeed := sha256.Sum256([]byte(t.Name()))
	accounts, balances := createTestAccountsAndBalances(t, 10, rootSeed[:])
	ledger := makeTestLedger(balances)

	subStrLogger := &substrServiceLogger{
		Logger:         logging.TestingLog(t),
		lookupStrings:  []string{"pseudonode.makeVotes: failed to enqueue vote verification for", "pseudonode.makeProposals: failed to enqueue vote verification"},
		instancesFound: []int{0, 0},
	}
	sLogger := serviceLogger{
		Logger: subStrLogger,
	}
	sLogger.SetLevel(logging.Warn)

	keyManager := makeRecordingKeyManager(accounts)

	mainPool := execpool.MakePool(t)
	defer mainPool.Shutdown()

	voteVerifier := MakeAsyncVoteVerifier(&expiredExecPool{mainPool})
	defer voteVerifier.Quit()

	pb := makePseudonode(pseudonodeParams{
		factory:      testBlockFactory{Owner: 0},
		validator:    testBlockValidator{},
		keys:         keyManager,
		ledger:       ledger,
		voteVerifier: voteVerifier,
		log:          sLogger,
		monitor:      nil,
	})
	defer pb.Quit()

	startRound := ledger.NextRound()

	channels := make([]<-chan externalEvent, 0)
	var ch <-chan externalEvent
	var err error
	for i := 0; i < pseudonodeVerificationBacklog*2; i++ {
		ch, err = pb.MakeProposals(context.Background(), startRound, period(i))
		if err != nil {
			require.ErrorIs(t, err, errPseudonodeBacklogFull)
			break
		}
		channels = append(channels, ch)
	}
	enqueuedProposals := len(channels)
	require.Error(t, err, "MakeProposals did not returned an error when being overflowed with requests")
	require.ErrorIs(t, err, errPseudonodeBacklogFull)

	persist := make(chan error)
	close(persist)
	for i := 0; i < pseudonodeVerificationBacklog*2; i++ {
		ch, err = pb.MakeVotes(context.Background(), startRound, period(i), step(i%5), makeProposalValue(period(i), accounts[0].Address()), persist)
		if err != nil {
			require.ErrorIs(t, err, errPseudonodeBacklogFull)
			break
		}
		channels = append(channels, ch)
	}
	require.Error(t, err, "MakeVotes did not returned an error when being overflowed with requests")
	enqueuedVotes := len(channels) - enqueuedProposals
	// drain output channels.
	for _, ch := range channels {
		drainChannel(ch)
	}
	require.Equal(t, enqueuedVotes*len(accounts), subStrLogger.instancesFound[0])
	require.Equal(t, enqueuedProposals*len(accounts), subStrLogger.instancesFound[1])
}
