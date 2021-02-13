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
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var proposalStoreTracer tracer

func init() {
	proposalStoreTracer.log = serviceLogger{logging.Base()}
}

func TestProposalStoreCreation(t *testing.T) {
	player, router, accounts, factory, ledger := testSetup(0)

	proposalVoteEventBatch, _, _ := createProposalEvents(t, player, accounts, factory, ledger)

	simulateProposalVotes(t, &router, &player, proposalVoteEventBatch)
}

func TestBlockAssemblerPipeline(t *testing.T) {
	type fields struct {
		Pipeline       unauthenticatedProposal
		Filled         bool
		Payload        proposal
		Assembled      bool
		Authenticators []vote
	}
	type args struct {
		p unauthenticatedProposal
	}

	player, _, accounts, factory, ledger := testSetup(0)

	round := player.Round
	period := player.Period
	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", round, err)

	accountIndex := 0
	proposal, _, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, period, ledger)
	accountIndex++

	uap := unauthenticatedProposal{}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    blockAssembler
		wantErr bool
	}{
		{name: "test", fields: fields{Pipeline: uap, Filled: false, Payload: proposal, Assembled: false, Authenticators: []vote{}},
			args:    args{},
			want:    blockAssembler{},
			wantErr: false},
		{name: "test", fields: fields{Pipeline: uap, Filled: true, Payload: proposal, Assembled: false, Authenticators: []vote{}},
			args:    args{},
			want:    blockAssembler{},
			wantErr: true},
		{name: "test", fields: fields{Pipeline: uap, Filled: false, Payload: proposal, Assembled: true, Authenticators: []vote{}},
			args:    args{},
			want:    blockAssembler{},
			wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := blockAssembler{
				Pipeline:       tt.fields.Pipeline,
				Filled:         tt.fields.Filled,
				Payload:        tt.fields.Payload,
				Assembled:      tt.fields.Assembled,
				Authenticators: tt.fields.Authenticators,
			}
			got, err := a.pipeline(tt.args.p)

			if (err != nil) != tt.wantErr {
				t.Errorf("blockAssembler.pipeline() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				require.NoError(t, err)
				require.NotNil(t, got)
			}
		})
	}
}

func TestBlockAssemblerBind(t *testing.T) {
	type fields struct {
		Pipeline       unauthenticatedProposal
		Filled         bool
		Payload        proposal
		Assembled      bool
		Authenticators []vote
	}
	type args struct {
		p proposal
	}

	player, _, accounts, factory, ledger := testSetup(0)

	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", player.Round, err)

	accountIndex := 0

	proposal, _, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, player.Period, ledger)
	accountIndex++

	uap := unauthenticatedProposal{}

	expectedEa := blockAssembler{
		Pipeline:       uap,
		Filled:         false,
		Payload:        proposal,
		Assembled:      true,
		Authenticators: []vote{},
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    blockAssembler
		wantErr bool
	}{
		{name: "test", fields: fields{Pipeline: uap, Filled: false, Payload: proposal, Assembled: false, Authenticators: []vote{}},
			args:    args{},
			want:    expectedEa,
			wantErr: false},
		{name: "test", fields: fields{Pipeline: uap, Filled: false, Payload: proposal, Assembled: true, Authenticators: []vote{}},
			args:    args{},
			want:    expectedEa,
			wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := blockAssembler{
				Pipeline:       tt.fields.Pipeline,
				Filled:         tt.fields.Filled,
				Payload:        tt.fields.Payload,
				Assembled:      tt.fields.Assembled,
				Authenticators: tt.fields.Authenticators,
			}
			_, err := a.bind(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("blockAssembler.bind() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestBlockAssemblerAuthenticator(t *testing.T) {
	type fields struct {
		Pipeline       unauthenticatedProposal
		Filled         bool
		Payload        proposal
		Assembled      bool
		Authenticators []vote
	}
	type args struct {
		p period
	}

	player, _, accounts, factory, ledger := testSetup(0)

	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", player.Round, err)
	accountIndex := 0
	proposalPayload, _, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, player.Period, ledger)

	currentAccount := accounts.addresses[accountIndex]

	uap := proposalPayload.unauthenticatedProposal

	voteAuthenticators := []vote{}

	block := makeRandomBlock(1)

	tempVote, err := makeVoteTesting(currentAccount, accounts.vrfs[accountIndex], accounts.ots[accountIndex], ledger, player.Round, player.Period, cert, block.Digest())
	require.NoError(t, err)

	voteAuthenticators = append(voteAuthenticators, tempVote)

	tests := []struct {
		name   string
		fields fields
		args   args
		want   vote
	}{
		// test cases
		{name: "test with vote authenticators", fields: fields{Pipeline: uap, Filled: false, Payload: proposalPayload, Assembled: false, Authenticators: voteAuthenticators},
			args: args{},
			want: tempVote,
		},
		{name: "test with no vote authenticators", fields: fields{Pipeline: uap, Filled: false, Payload: proposalPayload, Assembled: false, Authenticators: []vote{}},
			args: args{},
			want: vote{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := blockAssembler{
				Pipeline:       tt.fields.Pipeline,
				Filled:         tt.fields.Filled,
				Payload:        tt.fields.Payload,
				Assembled:      tt.fields.Assembled,
				Authenticators: tt.fields.Authenticators,
			}
			if got := a.authenticator(tt.args.p); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("blockAssembler.authenticator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlockAssemblerTrim(t *testing.T) {
	type fields struct {
		Pipeline       unauthenticatedProposal
		Filled         bool
		Payload        proposal
		Assembled      bool
		Authenticators []vote
	}
	type args struct {
		p period
	}

	player, _, accounts, factory, ledger := testSetup(0)

	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", player.Round, err)
	accountIndex := 0
	proposalPayload, _, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, player.Period, ledger)

	currentAccount := accounts.addresses[accountIndex]

	uap := proposalPayload.unauthenticatedProposal

	voteAuthenticators := []vote{}

	block, _ := makeRandomBlock(1), randomBlockHash()

	tempVote, err := makeVoteTesting(currentAccount, accounts.vrfs[accountIndex], accounts.ots[accountIndex], ledger, player.Round, player.Period, cert, block.Digest())
	require.NoError(t, err)

	voteAuthenticators = append(voteAuthenticators, tempVote)

	expectedEa1 := blockAssembler{
		Pipeline:       uap,
		Filled:         false,
		Payload:        proposalPayload,
		Assembled:      false,
		Authenticators: voteAuthenticators,
	}
	expectedEa2 := blockAssembler{
		Pipeline:       uap,
		Filled:         false,
		Payload:        proposalPayload,
		Assembled:      false,
		Authenticators: []vote{},
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   blockAssembler
	}{
		{name: "test trim with vote authenticators", fields: fields{Pipeline: uap, Filled: false, Payload: proposalPayload, Assembled: false, Authenticators: voteAuthenticators},
			args: args{p: player.Period},
			want: expectedEa1,
		},
		{name: "test trim with no vote authenticators", fields: fields{Pipeline: uap, Filled: false, Payload: proposalPayload, Assembled: false, Authenticators: []vote{}},
			args: args{p: player.Period},
			want: expectedEa2,
		},
		{name: "test trim with vote authenticators and different period", fields: fields{Pipeline: uap, Filled: false, Payload: proposalPayload, Assembled: false, Authenticators: voteAuthenticators},
			args: args{p: player.Period + 1},
			want: expectedEa2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := blockAssembler{
				Pipeline:       tt.fields.Pipeline,
				Filled:         tt.fields.Filled,
				Payload:        tt.fields.Payload,
				Assembled:      tt.fields.Assembled,
				Authenticators: tt.fields.Authenticators,
			}
			if got := a.trim(tt.args.p); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("blockAssembler.trim() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProposalStoreT(t *testing.T) {

	player, _, accounts, factory, ledger := testSetup(0)

	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", player.Round, err)
	accountIndex := 0
	proposalPayload, proposalV, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, player.Period, ledger)

	currentAccount := accounts.addresses[accountIndex]

	uap := proposalPayload.unauthenticatedProposal

	voteAuthenticators := []vote{}

	block, _ := makeRandomBlock(1), randomBlockHash()

	tempVote, err := makeVoteTesting(currentAccount, accounts.vrfs[accountIndex], accounts.ots[accountIndex], ledger, player.Round, player.Period, cert, block.Digest())
	require.NoError(t, err)

	voteAuthenticators = append(voteAuthenticators, tempVote)

	blockAssembly := blockAssembler{
		Pipeline:       uap,
		Filled:         false,
		Payload:        proposalPayload,
		Assembled:      false,
		Authenticators: voteAuthenticators,
	}

	relevantMap := make(map[period]proposalValue)
	relevantMap[player.Period] = proposalV

	assemblers := make(map[proposalValue]blockAssembler)
	assemblers[proposalV] = blockAssembly

	type fields struct {
		Relevant   map[period]proposalValue
		Pinned     proposalValue
		Assemblers map[proposalValue]blockAssembler
	}

	tests := []struct {
		name   string
		fields fields
		want   stateMachineTag
	}{
		// test cases

		{name: "test trim with vote authenticators and different period", fields: fields{Relevant: relevantMap, Pinned: proposalV, Assemblers: assemblers},
			want: proposalMachineRound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &proposalStore{
				Relevant:   tt.fields.Relevant,
				Pinned:     tt.fields.Pinned,
				Assemblers: tt.fields.Assemblers,
			}
			if got := store.T(); got != tt.want {
				t.Errorf("proposalStore.T() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProposalStoreUnderlying(t *testing.T) {
	type fields struct {
		Relevant   map[period]proposalValue
		Pinned     proposalValue
		Assemblers map[proposalValue]blockAssembler
	}

	player, _, accounts, factory, ledger := testSetup(0)

	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", player.Round, err)
	accountIndex := 0
	proposalPayload, proposalV, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, player.Period, ledger)

	currentAccount := accounts.addresses[accountIndex]

	uap := proposalPayload.unauthenticatedProposal

	voteAuthenticators := []vote{}

	block, _ := makeRandomBlock(1), randomBlockHash()

	tempVote, err := makeVoteTesting(currentAccount, accounts.vrfs[accountIndex], accounts.ots[accountIndex], ledger, player.Round, player.Period, cert, block.Digest())
	require.NoError(t, err)

	voteAuthenticators = append(voteAuthenticators, tempVote)

	blockAssembly := blockAssembler{
		Pipeline:       uap,
		Filled:         false,
		Payload:        proposalPayload,
		Assembled:      false,
		Authenticators: voteAuthenticators,
	}

	relevantMap := make(map[period]proposalValue)
	relevantMap[player.Period] = proposalV

	assemblers := make(map[proposalValue]blockAssembler)
	assemblers[proposalV] = blockAssembly

	tests := []struct {
		name   string
		fields fields
		want   listener
	}{
		// test cases.
		{name: "test underlying", fields: fields{Relevant: relevantMap, Pinned: proposalV, Assemblers: assemblers},
			want: &proposalStore{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &proposalStore{
				Relevant:   tt.fields.Relevant,
				Pinned:     tt.fields.Pinned,
				Assemblers: tt.fields.Assemblers,
			}
			got := store.underlying()
			require.True(t, reflect.DeepEqual(got.(*proposalStore).Assemblers, assemblers))
			require.True(t, reflect.DeepEqual(got.(*proposalStore).Pinned, proposalV))
			require.True(t, reflect.DeepEqual(got.(*proposalStore).Relevant, relevantMap))
		})
	}
}

func TestProposalStoreHandle(t *testing.T) {
	player, router, accounts, factory, ledger := testPlayerSetup()

	proposalVoteEventBatch, proposalPayloadEventBatch, _ := generateProposalEvents(t, player, accounts, factory, ledger)

	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", player.Round, err)
	accountIndex := 0
	_, proposalV0, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, player.Period, ledger)
	accountIndex++
	proposalPayload, proposalV, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, player.Period, ledger)

	currentAccount := accounts.addresses[accountIndex]

	uap := proposalPayload.unauthenticatedProposal

	voteAuthenticators := []vote{}

	block, _ := makeRandomBlock(1), randomBlockHash()

	tempVote, err := makeVoteTesting(currentAccount, accounts.vrfs[accountIndex], accounts.ots[accountIndex], ledger, player.Round, player.Period, cert, block.Digest())
	require.NoError(t, err)

	voteAuthenticators = append(voteAuthenticators, tempVote)

	blockAssembly := blockAssembler{
		Pipeline:       uap,
		Filled:         false,
		Payload:        proposalPayload,
		Assembled:      false,
		Authenticators: voteAuthenticators,
	}

	relevantMap := make(map[period]proposalValue)
	relevantMap[player.Period] = proposalV

	assemblers := make(map[proposalValue]blockAssembler)
	assemblers[proposalV] = blockAssembly

	player, _ = router.submitTop(&proposalStoreTracer, player, proposalVoteEventBatch[0])

	player, _ = router.submitTop(&proposalStoreTracer, player, proposalPayloadEventBatch[0])

	// create proposal Store
	testProposalStore := proposalStore{
		Relevant:   map[period]proposalValue{},
		Pinned:     proposalV,
		Assemblers: map[proposalValue]blockAssembler{},
	}

	// create a route handler for the proposal store
	rHandle := routerHandle{
		t:   &proposalStoreTracer,
		r:   &router,
		src: proposalMachinePeriod,
	}

	// Test a proposal payload event with non valid proposal payload
	msg := message{Tag: protocol.ProposalPayloadTag, Proposal: proposalPayload, UnauthenticatedProposal: proposalPayload.unauthenticatedProposal}
	testEvent := messageEvent{T: payloadPresent, Input: msg}
	returnEvent := testProposalStore.handle(rHandle, player, testEvent)
	require.Equal(t, returnEvent.(payloadProcessedEvent).T, payloadRejected)
	require.Equal(t, makeSerErrStr("proposalStore: no accepting blockAssembler found on payloadPresent"), returnEvent.(payloadProcessedEvent).Err)

	// Test a valid proposal payload event
	testProposalStore.Assemblers[proposalV] = blockAssembly
	testProposalStore.Relevant[player.Period] = proposalV
	testProposalStore.Pinned = proposalV

	returnEvent = testProposalStore.handle(rHandle, player, testEvent)
	require.Equal(t, payloadPipelined, returnEvent.(payloadProcessedEvent).T)

	// Test with blockAssembly in filled state which will fail pipeline test
	blockAssembly.Filled = true

	returnEvent = testProposalStore.handle(rHandle, player, testEvent)
	require.Equal(t, returnEvent.(payloadProcessedEvent).T, payloadRejected)
	require.Equal(t, makeSerErrStr("blockAssembler.pipeline: already filled"), returnEvent.(payloadProcessedEvent).Err)

	// create proposal Store
	testProposalStore = proposalStore{
		Relevant:   map[period]proposalValue{},
		Pinned:     proposalV,
		Assemblers: map[proposalValue]blockAssembler{},
	}

	// Test a proposal payload verified event with non valid proposal payload
	msg = message{Tag: protocol.ProposalPayloadTag, Proposal: proposalPayload, UnauthenticatedProposal: proposalPayload.unauthenticatedProposal}
	testEvent = messageEvent{T: payloadVerified, Input: msg}
	returnEvent = testProposalStore.handle(rHandle, player, testEvent)
	require.Equal(t, returnEvent.(payloadProcessedEvent).T, payloadRejected)
	require.Equal(t, makeSerErrStr("proposalStore: no accepting blockAssembler found on payloadVerified"), returnEvent.(payloadProcessedEvent).Err)

	// Test a valid payload verified event
	testProposalStore.Assemblers[proposalV] = blockAssembly
	testProposalStore.Relevant[player.Period] = proposalV
	testProposalStore.Relevant[player.Period+3] = proposalV0
	testProposalStore.Pinned = proposalV

	returnEvent = testProposalStore.handle(rHandle, player, testEvent)
	require.Equal(t, payloadAccepted, returnEvent.(payloadProcessedEvent).T)

	// Test a valid payload verified event with already assembled block assembly
	blockAssembly.Assembled = true

	returnEvent = testProposalStore.handle(rHandle, player, testEvent)
	require.Equal(t, payloadRejected, returnEvent.(payloadProcessedEvent).T)
	require.Equal(t, makeSerErrStr("blockAssembler.pipeline: already assembled"), returnEvent.(payloadProcessedEvent).Err)

	// Test a valid payload newPeriod event
	testProposalStore.Assemblers[proposalV] = blockAssembly
	testProposalStore.Relevant[player.Period] = proposalV
	testProposalStore.Pinned = proposalV

	msg = message{Tag: protocol.ProposalPayloadTag, Proposal: proposalPayload, UnauthenticatedProposal: proposalPayload.unauthenticatedProposal}
	testPeriodEvent := newPeriodEvent{Period: player.Period + 3, Proposal: proposalV}

	returnEvent = testProposalStore.handle(rHandle, player, testPeriodEvent)
	require.Equal(t, emptyEvent{}, returnEvent)

	msg = message{Tag: protocol.ProposalPayloadTag, Proposal: proposalPayload, UnauthenticatedProposal: proposalPayload.unauthenticatedProposal}
	testPeriodEvent = newPeriodEvent{Period: player.Period + 3, Proposal: bottom}

	returnEvent = testProposalStore.handle(rHandle, player, testPeriodEvent)
	require.Equal(t, emptyEvent{}, returnEvent)

	msg = message{Tag: protocol.ProposalPayloadTag, Proposal: proposalPayload, UnauthenticatedProposal: proposalPayload.unauthenticatedProposal}
	testNewRoundEvent := newRoundEvent{}

	// trigger too many assemblers panic in new Round event handling
	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() { testProposalStore.handle(rHandle, player, testNewRoundEvent) })
	logging.Base().SetOutput(os.Stderr)

	// return a payload pipelined event
	testProposalStore.Relevant = make(map[period]proposalValue)
	testProposalStore.Assemblers = make(map[proposalValue]blockAssembler)
	testProposalStore.Assemblers[proposalV] = blockAssembly
	testProposalStore.Relevant[player.Period] = proposalV

	returnEvent = testProposalStore.handle(rHandle, player, testNewRoundEvent)
	require.Equal(t, payloadPipelined, returnEvent.(payloadProcessedEvent).T)

	// test soft threshold event
	testThresholdEvent := thresholdEvent{
		T:        softThreshold,
		Round:    player.Round,
		Period:   player.Period,
		Step:     player.Step,
		Proposal: proposalV,
		Bundle:   unauthenticatedBundle{},
	}
	returnEvent = testProposalStore.handle(rHandle, player, testThresholdEvent)
	require.Equal(t, testProposalStore.Pinned, returnEvent.(committableEvent).Proposal)

	testStagingValueEvent := stagingValueEvent{
		Round:  player.Round,
		Period: player.Period,
	}
	returnEvent = testProposalStore.handle(rHandle, player, testStagingValueEvent)
	require.Equal(t, proposalV, returnEvent.(stagingValueEvent).Proposal)
	require.Equal(t, proposalPayload, returnEvent.(stagingValueEvent).Payload)
	require.True(t, returnEvent.(stagingValueEvent).Committable)

	testPinnedValueEvent := pinnedValueEvent{
		Round: player.Round,
	}
	returnEvent = testProposalStore.handle(rHandle, player, testPinnedValueEvent)
	require.Equal(t, proposalV, returnEvent.(pinnedValueEvent).Proposal)
	require.Equal(t, proposalPayload, returnEvent.(pinnedValueEvent).Payload)
	require.True(t, returnEvent.(pinnedValueEvent).PayloadOK)

	msg = message{Tag: protocol.ProposalPayloadTag, Proposal: proposalPayload, UnauthenticatedProposal: proposalPayload.unauthenticatedProposal}
	testEvent = messageEvent{T: roundInterruption, Input: msg}

	// trigger panic from non supported message type
	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() { testProposalStore.handle(rHandle, player, testEvent) })
	logging.Base().SetOutput(os.Stderr)

	// test trim
	testProposalStore.trim(player)
}

func TestProposalStoreGetPinnedValue(t *testing.T) {
	// create proposal Store
	player, router, accounts, factory, ledger := testPlayerSetup()
	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", player.Round, err)
	accountIndex := 0
	// create a route handler for the proposal store
	rHandle := routerHandle{
		t:   &proposalStoreTracer,
		r:   &router,
		src: proposalMachinePeriod,
	}
	payloadV, proposalV, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, player.Period, ledger)

	testProposalStore := proposalStore{
		Relevant:   map[period]proposalValue{},
		Pinned:     proposalV,
		Assemblers: map[proposalValue]blockAssembler{},
	}

	// Check that we get pinned value, but no block; payloadOK must be false
	testPinnedValueEvent := pinnedValueEvent{
		Round: player.Round,
	}
	returnEvent := testProposalStore.handle(rHandle, player, testPinnedValueEvent)
	require.Equal(t, proposalV, returnEvent.(pinnedValueEvent).Proposal)
	require.Falsef(t, returnEvent.(pinnedValueEvent).PayloadOK, "Get pinned value cannot set payloadOK if no block assembled")
	require.Equal(t, proposal{}.value(), returnEvent.(pinnedValueEvent).Payload.value())

	// now, assemble it. This is unfortunately, quite white box
	// even w.r.t. the proposalStore, until we have the infra for blackbox proposal store testing.
	var ea blockAssembler
	testProposalStore.Assemblers[proposalV] = ea
	msgP1 := message{
		Tag:                     protocol.ProposalPayloadTag,
		Proposal:                payloadV,
		UnauthenticatedProposal: payloadV.u(),
	}
	assemblePayloadEv := messageEvent{T: payloadVerified, Input: msgP1}
	returnEvent = testProposalStore.handle(rHandle, player, assemblePayloadEv)
	require.Equal(t, payloadAccepted, returnEvent.t())

	// Getting pinned value should now also return block
	testPinnedValueEvent = pinnedValueEvent{
		Round: player.Round,
	}
	returnEvent = testProposalStore.handle(rHandle, player, testPinnedValueEvent)
	require.Equal(t, proposalV, returnEvent.(pinnedValueEvent).Proposal)
	require.Equal(t, proposalV, returnEvent.(pinnedValueEvent).Payload.value())
	require.Truef(t, returnEvent.(pinnedValueEvent).PayloadOK, "Get Pinned Value must get assembled block")
}

func TestProposalStoreRegressionBlockRedeliveryBug_b29ea57(t *testing.T) {
	var msgV1, msgV2, msgP1, msgP2 message
	var rv rawVote
	var propVal proposalValue
	var propPay proposal
	curRound := round(10)
	proposer := basics.Address(randomBlockHash())

	propPay = proposal{
		unauthenticatedProposal: unauthenticatedProposal{
			OriginalPeriod:   1,
			OriginalProposer: proposer,
		},
	}
	propVal = proposalValue{
		OriginalPeriod:   1,
		OriginalProposer: proposer,
		BlockDigest:      propPay.Digest(),
		EncodingDigest:   crypto.HashObj(propPay),
	}
	propPay.pv = propVal
	rv = rawVote{
		Sender:   proposer,
		Round:    curRound,
		Period:   1,
		Proposal: propVal,
	}
	msgV1 = message{
		Tag:                 protocol.AgreementVoteTag,
		Vote:                vote{R: rv},
		UnauthenticatedVote: unauthenticatedVote{R: rv},
	}
	msgP1 = message{
		Tag:                     protocol.ProposalPayloadTag,
		Proposal:                propPay,
		UnauthenticatedProposal: propPay.u(),
	}

	propPay = proposal{
		unauthenticatedProposal: unauthenticatedProposal{
			OriginalPeriod:   2,
			OriginalProposer: proposer,
		},
	}
	propVal = proposalValue{
		OriginalPeriod:   2,
		OriginalProposer: proposer,
		BlockDigest:      propPay.Digest(),
		EncodingDigest:   crypto.HashObj(propPay),
	}
	propPay.pv = propVal
	rv = rawVote{
		Sender:   proposer,
		Round:    curRound,
		Period:   2,
		Proposal: propVal,
	}
	msgV2 = message{
		Tag:                 protocol.AgreementVoteTag,
		Vote:                vote{R: rv},
		UnauthenticatedVote: unauthenticatedVote{R: rv},
	}
	msgP2 = message{
		Tag:                     protocol.ProposalPayloadTag,
		Proposal:                propPay,
		UnauthenticatedProposal: propPay.u(),
	}

	period1Trigger := newPeriodEvent{Period: 1, Proposal: bottom}
	propVote1Receipt := messageEvent{T: voteVerified, Input: msgV1}
	propPayload1Receipt := messageEvent{T: payloadVerified, Input: msgP1}
	period2Trigger := newPeriodEvent{Period: 2, Proposal: bottom}
	propVote2Receipt := messageEvent{T: voteVerified, Input: msgV2}
	propPayload2Receipt := messageEvent{T: payloadVerified, Input: msgP2}

	// due to map iteration order, the test may succeed despite a logic bug,
	// so we repeat until we are reasonably confident the bug is not present.
	for i := 0; i < 10; i++ {
		player := player{Round: curRound}

		var router router
		rr := routerFixture
		router = &rr

		var res event

		res = router.dispatch(&proposalStoreTracer, player, period1Trigger, playerMachine, proposalMachineRound, curRound, 1, 0)
		require.Equal(t, res.t(), none)

		res = router.dispatch(&proposalStoreTracer, player, propVote1Receipt, playerMachine, proposalMachineRound, curRound, 1, 0)
		require.Equal(t, res.t(), proposalAccepted)

		res = router.dispatch(&proposalStoreTracer, player, propPayload1Receipt, playerMachine, proposalMachineRound, curRound, 1, 0)
		require.Equal(t, res.t(), payloadAccepted)

		res = router.dispatch(&proposalStoreTracer, player, period2Trigger, playerMachine, proposalMachineRound, curRound, 2, 0)
		require.Equal(t, res.t(), none)

		res = router.dispatch(&proposalStoreTracer, player, propVote2Receipt, playerMachine, proposalMachineRound, curRound, 2, 0)
		require.Equal(t, res.t(), proposalAccepted)

		res = router.dispatch(&proposalStoreTracer, player, propPayload2Receipt, playerMachine, proposalMachineRound, curRound, 2, 0)
		if res.t() == payloadRejected {
			t.Fatalf("bug b29ea57: a proposal with a new original period collides with a proposal from an old original period")
		} else {
			require.Equal(t, res.t(), payloadAccepted)
		}
	}

}

func TestProposalStoreRegressionWrongPipelinePeriodBug_39387501(t *testing.T) {
	var msgV1, msgV2, msgP1, msgP2 message
	var rv rawVote
	var propVal proposalValue
	var propPay proposal
	curRound := round(10)
	proposer := basics.Address(randomBlockHash())

	propPay = proposal{
		unauthenticatedProposal: unauthenticatedProposal{
			OriginalPeriod:   1,
			OriginalProposer: proposer,
		},
	}
	propVal = proposalValue{
		OriginalPeriod:   1,
		OriginalProposer: proposer,
		BlockDigest:      propPay.Digest(),
		EncodingDigest:   crypto.HashObj(propPay),
	}
	rv = rawVote{
		Sender:   proposer,
		Round:    curRound,
		Period:   1,
		Proposal: propVal,
	}
	msgV1 = message{
		Tag:                 protocol.AgreementVoteTag,
		Vote:                vote{R: rv},
		UnauthenticatedVote: unauthenticatedVote{R: rv},
	}
	msgP1 = message{
		Tag:                     protocol.ProposalPayloadTag,
		Proposal:                propPay,
		UnauthenticatedProposal: propPay.u(),
	}

	propPay = proposal{
		unauthenticatedProposal: unauthenticatedProposal{
			OriginalPeriod:   2,
			OriginalProposer: proposer,
		},
	}
	propVal = proposalValue{
		OriginalPeriod:   2,
		OriginalProposer: proposer,
		BlockDigest:      propPay.Digest(),
		EncodingDigest:   crypto.HashObj(propPay),
	}
	rv = rawVote{
		Sender:   proposer,
		Round:    curRound,
		Period:   2,
		Proposal: propVal,
	}
	msgV2 = message{
		Tag:                 protocol.AgreementVoteTag,
		Vote:                vote{R: rv},
		UnauthenticatedVote: unauthenticatedVote{R: rv},
	}
	msgP2 = message{
		Tag:                     protocol.ProposalPayloadTag,
		Proposal:                propPay,
		UnauthenticatedProposal: propPay.u(),
	}

	period1Trigger := newPeriodEvent{Period: 1, Proposal: bottom}
	propVote1Receipt := messageEvent{T: voteVerified, Input: msgV1}
	propPayload1Receipt := messageEvent{T: payloadPresent, Input: msgP1}
	period2Trigger := newPeriodEvent{Period: 2, Proposal: bottom}
	propVote2Receipt := messageEvent{T: voteVerified, Input: msgV2}
	propPayload2Receipt := messageEvent{T: payloadPresent, Input: msgP2}

	player := player{Round: curRound}

	var router router
	rr := routerFixture
	router = &rr

	var res event

	res = router.dispatch(&proposalStoreTracer, player, period1Trigger, playerMachine, proposalMachineRound, curRound, 1, 0)
	require.Equal(t, res.t(), none)

	res = router.dispatch(&proposalStoreTracer, player, propVote1Receipt, playerMachine, proposalMachineRound, curRound, 1, 0)
	require.Equal(t, res.t(), proposalAccepted)

	res = router.dispatch(&proposalStoreTracer, player, period2Trigger, playerMachine, proposalMachineRound, curRound, 2, 0)
	require.Equal(t, res.t(), none)

	res = router.dispatch(&proposalStoreTracer, player, propVote2Receipt, playerMachine, proposalMachineRound, curRound, 2, 0)
	require.Equal(t, res.t(), proposalAccepted)

	res = router.dispatch(&proposalStoreTracer, player, propPayload2Receipt, playerMachine, proposalMachineRound, curRound, 2, 0)
	require.Equal(t, res.t(), payloadPipelined)
	require.Equal(t, res.(payloadProcessedEvent).Period, period(2))

	res = router.dispatch(&proposalStoreTracer, player, propPayload1Receipt, playerMachine, proposalMachineRound, curRound, 1, 0)
	if res.(payloadProcessedEvent).Period == 2 {
		t.Fatalf("bug b29ea57: a proposal corresponding to an old period is erroneously seen as as corresponding to a new period")
	} else {
		require.Equal(t, res.t(), payloadPipelined)
		require.Equal(t, res.(payloadProcessedEvent).Period, period(1))
	}
}
