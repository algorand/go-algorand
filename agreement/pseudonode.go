// Copyright (C) 2019-2020 Algorand, Inc.
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
	"sync"
	"time"

	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/logspec"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
)

// AssemblyTime is the max amount of time to spend on generating a proposal block.
const AssemblyTime time.Duration = 250 * time.Millisecond

// TODO put these in config
const (
	pseudonodeVerificationBacklog = 32
)

var errPseudonodeBacklogFull = fmt.Errorf("pseudonode input channel is full")
var errPseudonodeVerifierClosedChannel = fmt.Errorf("crypto verifier closed the output channel prematurely")
var errPseudonodeNoVotes = fmt.Errorf("no valid participation keys to generate votes for given round")
var errPseudonodeNoProposals = fmt.Errorf("no valid participation keys to generate proposals for given round")

// A pseudonode creates proposals and votes with a KeyManager which holds participation keys.
//
// It constructs these messages as if they arrived from an external source and were verified.
// These messages are processed and relayed by the state machine just like any other message from an external source.
// This design simplifies the logic required to test and execute proposing and voting.
type pseudonode interface {
	// MakeProposals returns a channel which contains all proposals for the given round and period.
	//
	// The passed-in context may be used to cancel proposal creation and close the channel immediately.
	//
	// It returns an error if the pseudonode is unable to perform this.
	MakeProposals(ctx context.Context, r round, p period) (<-chan externalEvent, error)

	// MakeVotes returns a vote for a given proposal in some round, period, and step.
	//
	// The passed-in context may be used to cancel vote creation and close the channel immediately.
	//
	// It returns an error if the pseudonode is unable to perform this.
	MakeVotes(ctx context.Context, r round, p period, s step, prop proposalValue, persistStateDone chan error) (chan externalEvent, error)

	// Quit directs the pseudonode to exit.
	Quit()
}

// asyncPseudonode creates proposals and votes asynchronously.
type asyncPseudonode struct {
	factory   BlockFactory
	validator BlockValidator
	keys      KeyManager
	ledger    Ledger
	log       serviceLogger
	quit      chan struct{}   // a quit signal for the verifier goroutines
	closeWg   *sync.WaitGroup // frontend waitgroup to get notified when all the verifier goroutines are done.
	monitor   *coserviceMonitor

	proposalsVerifier *pseudonodeVerifier // dynamically generated verifier goroutine that manages incoming proposals making request.
	votesVerifier     *pseudonodeVerifier // dynamically generated verifier goroutine that manages incoming votes making request.
}

// pseudonodeTask encapsulates a single task which should be executed by the pseudonode.
type pseudonodeTask interface {
	// Execute a task with quit channel.
	execute(quit chan struct{})
}

type selectedParticipant struct {
	participant account.Participation
	cred        committee.Credential
}

type pseudonodeBaseTask struct {
	node          *asyncPseudonode
	context       context.Context // the context associated with that task; context might expire for a single task but remain valid for others.
	out           chan externalEvent
	participation []selectedParticipant
}

type pseudonodeVotesTask struct {
	pseudonodeBaseTask
	round            round
	period           period
	step             step
	prop             proposalValue
	persistStateDone chan error
}

type pseudonodeProposalsTask struct {
	pseudonodeBaseTask
	round  round
	period period
}

type pseudonodeVerifier struct {
	incomingTasks chan pseudonodeTask
}

type verifiedCryptoResults []asyncVerifyVoteResponse

func makePseudonode(factory BlockFactory, validator BlockValidator, keys KeyManager, ledger Ledger, log serviceLogger) pseudonode {
	pn := asyncPseudonode{
		factory:   factory,
		validator: validator,
		keys:      keys,
		ledger:    ledger,
		log:       log,
		quit:      make(chan struct{}),
		closeWg:   &sync.WaitGroup{},
	}

	pn.proposalsVerifier = pn.makePseudonodeVerifier()
	pn.votesVerifier = pn.makePseudonodeVerifier()
	return pn
}

func (n asyncPseudonode) Quit() {
	// protect against double-quits.
	select {
	case <-n.quit:
		// if we already quit, just exit.
		return
	default:
	}
	close(n.quit)
	n.proposalsVerifier.close()
	n.votesVerifier.close()
	n.closeWg.Wait()
}

func (n asyncPseudonode) MakeProposals(ctx context.Context, r round, p period) (<-chan externalEvent, error) {
	proposalTask := n.makeProposalsTask(ctx, r, p)

	if len(proposalTask.participation) == 0 {
		// no proposals are generated as there are no participation keys.
		return proposalTask.out, errPseudonodeNoProposals
	}

	n.monitor.inc(pseudonodeCoserviceType)
	select {
	case n.proposalsVerifier.incomingTasks <- proposalTask:
		return proposalTask.outputChannel(), nil
	default:
		proposalTask.close()
		return nil, errPseudonodeBacklogFull
	}
}

func (n asyncPseudonode) MakeVotes(ctx context.Context, r round, p period, s step, prop proposalValue, persistStateDone chan error) (chan externalEvent, error) {
	proposalTask := n.makeVotesTask(ctx, r, p, s, prop, persistStateDone)
	if len(proposalTask.participation) == 0 {
		// no votes are generated as there are no participation keys.
		return proposalTask.out, errPseudonodeNoVotes
	}

	n.monitor.inc(pseudonodeCoserviceType)
	select {
	case n.votesVerifier.incomingTasks <- proposalTask:
		return proposalTask.outputChannel(), nil
	default:
		proposalTask.close()
		return nil, errPseudonodeBacklogFull
	}
}

func (n asyncPseudonode) makeProposalsTask(ctx context.Context, r round, p period) pseudonodeProposalsTask {
	participation := n.getParticipations("asyncPseudonode.makeProposalsTask", r, p, propose)

	pt := pseudonodeProposalsTask{
		pseudonodeBaseTask: pseudonodeBaseTask{
			node:          &n,
			context:       ctx,
			participation: participation,
			out:           make(chan externalEvent),
		},
		round:  r,
		period: p,
	}
	if len(participation) == 0 {
		close(pt.out)
	}
	return pt
}

func (n asyncPseudonode) makeVotesTask(ctx context.Context, r round, p period, s step, prop proposalValue, persistStateDone chan error) pseudonodeVotesTask {
	participation := n.getParticipations("asyncPseudonode.makeVotesTask", r, p, s)

	pvt := pseudonodeVotesTask{
		pseudonodeBaseTask: pseudonodeBaseTask{
			node:          &n,
			context:       ctx,
			participation: participation,
			out:           make(chan externalEvent),
		},
		round:            r,
		period:           p,
		step:             s,
		prop:             prop,
		persistStateDone: persistStateDone,
	}
	if len(participation) == 0 {
		close(pvt.out)
	}
	return pvt
}

func (n asyncPseudonode) makePseudonodeVerifier() *pseudonodeVerifier {
	pv := &pseudonodeVerifier{
		incomingTasks: make(chan pseudonodeTask, pseudonodeVerificationBacklog),
	}
	n.closeWg.Add(1)
	go pv.verifierLoop(&n)
	return pv
}

// getParticipations retrieves the participation accounts for a given round.
func (n asyncPseudonode) getParticipations(procName string, round basics.Round, p period, s step) []selectedParticipant {
	keys := n.keys.Keys()
	participations := make([]account.Participation, 0, len(keys))

	for _, part := range keys {
		firstValid, lastValid := part.ValidInterval()
		if round < firstValid || round > lastValid {
			n.log.Debugf("%v (round=%v): Account %v not participating: %v not in [%v, %v]", procName, round, part.Address(), round, firstValid, lastValid)
			continue
		}
		participations = append(participations, part)
	}
	if len(participations) == 0 {
		return []selectedParticipant{}
	}

	proto, err := n.ledger.ConsensusParams(ParamsRound(round))
	if err != nil {
		return []selectedParticipant{}
	}

	seedRound := seedRound(round, proto)
	seed, err := n.ledger.Seed(seedRound)
	if err != nil {
		err = fmt.Errorf("asyncPseudonode.getParticipations (r=%d): Failed to obtain seed in round %d: %v", round, seedRound, err)
		return []selectedParticipant{}
	}
	balanceRound := balanceRound(round, proto)
	total, err := n.ledger.Circulation(balanceRound)
	if err != nil {
		err = fmt.Errorf("asyncPseudonode.getParticipations (r=%d): Failed to obtain total circulation in round %d: %v", round, balanceRound, err)
		return []selectedParticipant{}
	}

	sel := makeSelector(seed, round, p, s)
	selectedParticipants := make([]selectedParticipant, 0, len(participations))

	for _, part := range participations {
		record, err := n.ledger.BalanceRecord(balanceRound, part.Address())
		if err != nil {
			continue
		}

		cred := committee.MakeCredential(&part.VRFSecrets().SK, sel)
		authCred, err := cred.Verify(proto, committee.Membership{Record: record, Selector: sel, TotalMoney: total})
		if err != nil {
			// account not selected.
			continue
		}

		selectedParticipants = append(selectedParticipants, selectedParticipant{participant: part, cred: authCred})
	}

	return selectedParticipants
}

// makeProposals creates a slice of block proposals for the given round and period.
func (n asyncPseudonode) makeProposals(round basics.Round, period period, selectedAccounts []selectedParticipant) ([]proposal, []vote) {
	deadline := time.Now().Add(AssemblyTime)
	ve, err := n.factory.AssembleBlock(round, deadline)
	if err != nil {
		n.log.Errorf("pseudonode.makeProposals: could not generate a proposal for round %d: %v", round, err)
		return nil, nil
	}

	votes := make([]vote, 0, len(selectedAccounts))
	proposals := make([]proposal, 0, len(selectedAccounts))
	proto, err := n.ledger.ConsensusParams(ParamsRound(round))
	if err != nil {
		n.log.Warnf("pseudonode.makeProposals: could not get consensus params for round %d: %v", ParamsRound(round), err)
		return nil, nil
	}
	for _, selectedParticipant := range selectedAccounts {
		account := selectedParticipant.participant
		payload, proposal, err := proposalForBlock(account.Address(), account.VRFSecrets(), ve, period, n.ledger)
		if err != nil {
			n.log.Errorf("pseudonode.makeProposals: could not create proposal for block (address %v): %v", account.Address(), err)
			continue
		}

		// attempt to make the vote
		rv := rawVote{Sender: account.Address(), Round: round, Period: period, Step: propose, Proposal: proposal}
		uv, err := makeVote(rv, account.VotingSigner(), selectedParticipant.cred, proto)
		if err != nil {
			n.log.Warnf("pseudonode.makeProposals: could not create vote: %v", err)
			continue
		}

		// create the block proposal
		proposals = append(proposals, payload)
		votes = append(votes, uv)
	}

	return proposals, votes
}

// makeVotes creates a slice of votes for a given proposal value in a given
// round, period, and step.
func (n asyncPseudonode) makeVotes(round basics.Round, period period, step step, proposal proposalValue, participation []selectedParticipant) []vote {
	votes := make([]vote, 0, len(participation))
	proto, err := n.ledger.ConsensusParams(ParamsRound(round))
	if err != nil {
		n.log.Warnf("pseudonode.makeVotes: could not get consensus params for round %d: %v", ParamsRound(round), err)
		return nil
	}
	for _, selectedParticipant := range participation {
		account := selectedParticipant.participant
		rv := rawVote{Sender: account.Address(), Round: round, Period: period, Step: step, Proposal: proposal}
		vote, err := makeVote(rv, account.VotingSigner(), selectedParticipant.cred, proto)
		if err != nil {
			n.log.Warnf("pseudonode.makeVotes: could not create vote: %v", err)
			continue
		}
		votes = append(votes, vote)
	}
	return votes
}

func (pv *pseudonodeVerifier) close() {
	close(pv.incomingTasks)
}

func (pv *pseudonodeVerifier) verifierLoop(n *asyncPseudonode) {
	defer n.closeWg.Done()
	var ok bool
	var task pseudonodeTask
	for {
		select {
		case <-n.quit:
			// if we're done, we should close this one.
			return
		case task, ok = <-pv.incomingTasks:
			if !ok {
				// incoming tasks channel closed.
				return
			}
		}
		task.execute(n.quit)
	}
}

func (t pseudonodeBaseTask) outputChannel() chan externalEvent {
	return t.out
}

func (t pseudonodeBaseTask) close() {
	close(t.out)
}

func (t pseudonodeVotesTask) execute(quit chan struct{}) {
	defer t.close()

	// check to see if task already expired.
	if t.context.Err() != nil {
		return
	}

	votes := t.node.makeVotes(t.round, t.period, t.step, t.prop, t.participation)
	t.node.log.Infof("pseudonode: made %v votes", len(votes))

	var totalWeight uint64
	for _, vote := range votes {
		totalWeight += vote.Cred.Weight
	}
	for _, vote := range votes {
		logEvent := logspec.AgreementEvent{
			Type:         logspec.VoteBroadcast,
			Sender:       vote.R.Sender.String(),
			Hash:         vote.R.Proposal.BlockDigest.String(),
			ObjectRound:  uint64(vote.R.Round),
			ObjectPeriod: uint64(vote.R.Period),
			ObjectStep:   uint64(vote.R.Step),
			Weight:       vote.Cred.Weight,
			WeightTotal:  totalWeight,
		}
		t.node.log.with(logEvent).Infof("vote created for broadcast (weight %v, total weight %v)", vote.Cred.Weight, totalWeight)
		t.node.log.EventWithDetails(telemetryspec.Agreement, telemetryspec.VoteSentEvent, telemetryspec.VoteEventDetails{
			Address: vote.R.Sender.String(),
			Hash:    vote.R.Proposal.BlockDigest.String(),
			Round:   uint64(vote.R.Round),
			Period:  uint64(vote.R.Period),
			Step:    uint64(vote.R.Step),
			Weight:  vote.Cred.Weight,
			// Recovered: false,
		})
	}
	t.node.log.Infof("pseudonode.makeVotes: %v votes created for %v at (%v, %v, %v), total weight %v", len(votes), t.prop, t.round, t.period, t.step, totalWeight)

	if len(votes) > 0 {
		// wait until the persist state is flushed, as we don't want to send any vote unless we've completed flushing it to disk.
		// at this point, the error was already logged.
		select {
		case err, ok := <-t.persistStateDone:
			if ok && err != nil {
				// we were unable to persist to disk; dont sent any votes.
				t.node.log.Warnf("pseudonode.makeVotes: %v votes dropped due to disk persistence failuire : %v", len(votes), err)
				return
			}
		case <-quit:
			return
		case <-t.context.Done():
			// we done care about the output anymore; just exit.
			return
		}
	}

	for range votes {
		t.node.monitor.inc(pseudonodeCoserviceType)
	}
	t.node.monitor.dec(pseudonodeCoserviceType)

	// push results into channel.
	for _, vote := range votes {
		select {
		case t.out <- messageEvent{
			T: voteVerified,
			Input: message{
				Tag:                 protocol.AgreementVoteTag,
				UnauthenticatedVote: vote.u(),
				Vote:                vote},
			Err: makeSerErr(nil)}:
		case <-quit:
			return
		case <-t.context.Done():
			// we done care about the output anymore; just exit.
			return
		}
	}
}

func (t pseudonodeProposalsTask) execute(quit chan struct{}) {
	defer t.close()

	// check to see if task already expired.
	if t.context.Err() != nil {
		return
	}

	payloads, votes := t.node.makeProposals(t.round, t.period, t.participation)
	fields := logging.Fields{
		"Context":      "Agreement",
		"Type":         logspec.ProposalAssembled.String(),
		"ObjectRound":  t.round,
		"ObjectPeriod": t.period,
		"WeightTotal":  len(votes),
	}
	t.node.log.WithFields(fields).Infof("pseudonode: made %v proposals", len(votes))

	// We used to record block assembly time in timer info, but not anymore.
	// Previously we were using the state machine tracer.timeR(), which caused a data race. (GOAL2-541)
	// It's not immediately obvious how to log a diff, we may need to change the interface.
	// For now, don't log at all, and revisit when the metric becomes more important.

	for _, vote := range votes {

		logEvent := logspec.AgreementEvent{
			Type:         logspec.ProposalBroadcast,
			Hash:         vote.R.Proposal.BlockDigest.String(),
			ObjectRound:  uint64(vote.R.Round),
			ObjectPeriod: uint64(vote.R.Period),
		}
		t.node.log.with(logEvent).Infof("pseudonode.makeProposals: proposal created for (%d, %d)", vote.R.Round, vote.R.Period)
		t.node.log.EventWithDetails(telemetryspec.Agreement, telemetryspec.BlockProposedEvent, telemetryspec.BlockProposedEventDetails{
			Hash:    vote.R.Proposal.BlockDigest.String(),
			Address: vote.R.Sender.String(),
			Round:   uint64(vote.R.Round),
			Period:  uint64(vote.R.Period),
		})
	}
	t.node.log.Infof("pseudonode.makeProposals: %d proposals created for round %d, period %d", len(votes), t.round, t.period)

	for range votes {
		t.node.monitor.inc(pseudonodeCoserviceType)
	}
	for range payloads {
		t.node.monitor.inc(pseudonodeCoserviceType)
	}
	t.node.monitor.dec(pseudonodeCoserviceType)

	// push results into channel.
	for _, r := range votes {
		select {
		case t.out <- messageEvent{
			T: voteVerified,
			Input: message{
				Tag:                 protocol.AgreementVoteTag,
				UnauthenticatedVote: r.u(),
				Vote:                r},
			Err: makeSerErr(nil)}:
		case <-quit:
			return
		case <-t.context.Done():
			// we done care about the output anymore; just exit.
			return
		}
	}

	for _, payload := range payloads {
		msg := message{Tag: protocol.ProposalPayloadTag, UnauthenticatedProposal: payload.u(), Proposal: payload}
		select {
		case t.out <- messageEvent{T: payloadVerified, Input: msg}:
		case <-quit:
			return
		case <-t.context.Done():
			// we done care about the output anymore; just exit.
			return
		}
	}
}
