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
	"sync"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/logspec"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
)

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
	factory                BlockFactory
	validator              BlockValidator
	keys                   KeyManager
	ledger                 Ledger
	log                    serviceLogger
	quit                   chan struct{}   // a quit signal for the verifier goroutines
	closeWg                *sync.WaitGroup // frontend waitgroup to get notified when all the verifier goroutines are done.
	monitor                *coserviceMonitor
	participationKeysRound basics.Round            // the round to which the participationKeys matches
	participationKeys      []account.Participation // the list of the participation keys for round participationKeysRound

	proposalsVerifier *pseudonodeVerifier // dynamically generated verifier goroutine that manages incoming proposals making request.
	votesVerifier     *pseudonodeVerifier // dynamically generated verifier goroutine that manages incoming votes making request.
}

// pseudonodeTask encapsulates a single task which should be executed by the pseudonode.
type pseudonodeTask interface {
	// Execute a task with a given cryptoVerifier and quit channel.
	execute(verifier *AsyncVoteVerifier, quit chan struct{})
}

type pseudonodeBaseTask struct {
	node          *asyncPseudonode
	context       context.Context // the context associated with that task; context might expire for a single task but remain valid for others.
	out           chan externalEvent
	participation []account.Participation
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
	verifier      *AsyncVoteVerifier
	incomingTasks chan pseudonodeTask
}

//msgp:ignore verifiedCryptoResults
type verifiedCryptoResults []asyncVerifyVoteResponse

// pseudonodeParams struct provide the parameters required to create a pseudonode
type pseudonodeParams struct {
	factory      BlockFactory
	validator    BlockValidator
	keys         KeyManager
	ledger       Ledger
	voteVerifier *AsyncVoteVerifier
	log          serviceLogger
	monitor      *coserviceMonitor
}

func makePseudonode(params pseudonodeParams) pseudonode {
	pn := asyncPseudonode{
		factory:   params.factory,
		validator: params.validator,
		keys:      params.keys,
		ledger:    params.ledger,
		log:       params.log,
		quit:      make(chan struct{}),
		closeWg:   &sync.WaitGroup{},
		monitor:   params.monitor,
	}

	pn.proposalsVerifier = pn.makePseudonodeVerifier(params.voteVerifier)
	pn.votesVerifier = pn.makePseudonodeVerifier(params.voteVerifier)
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

// load the participation keys from the account manager ( as needed ) for the
// current round.
func (n *asyncPseudonode) loadRoundParticipationKeys(voteRound basics.Round) []account.Participation {
	// if we've already loaded up the keys, then just skip loading them.
	if n.participationKeysRound == voteRound {
		return n.participationKeys
	}

	cparams, err := n.ledger.ConsensusParams(ParamsRound(voteRound))
	if err != nil {
		// if we cannot figure out the balance round number, reset the parameters so that we won't be sending
		// any vote.
		n.log.Warnf("asyncPseudonode: unable to retrieve consensus parameters for voting round %d : %v", voteRound, err)
		n.participationKeysRound = basics.Round(0)
		n.participationKeys = nil
		return nil
	}
	balanceRound := balanceRound(voteRound, cparams)

	// otherwise, we want to load the participation keys.
	n.participationKeys = n.keys.VotingKeys(voteRound, balanceRound)
	n.participationKeysRound = voteRound
	return n.participationKeys
}

func (n asyncPseudonode) makeProposalsTask(ctx context.Context, r round, p period) pseudonodeProposalsTask {
	pt := pseudonodeProposalsTask{
		pseudonodeBaseTask: pseudonodeBaseTask{
			node:    &n,
			context: ctx,
			out:     make(chan externalEvent),
		},
		round:  r,
		period: p,
	}
	if !pt.populateParticipationKeys(r) {
		close(pt.out)
	}
	return pt
}

func (n asyncPseudonode) makeVotesTask(ctx context.Context, r round, p period, s step, prop proposalValue, persistStateDone chan error) pseudonodeVotesTask {
	pvt := pseudonodeVotesTask{
		pseudonodeBaseTask: pseudonodeBaseTask{
			node:    &n,
			context: ctx,
			out:     make(chan externalEvent),
		},
		round:            r,
		period:           p,
		step:             s,
		prop:             prop,
		persistStateDone: persistStateDone,
	}
	if !pvt.populateParticipationKeys(r) {
		close(pvt.out)
	}
	return pvt
}

func (n asyncPseudonode) makePseudonodeVerifier(voteVerifier *AsyncVoteVerifier) *pseudonodeVerifier {
	pv := &pseudonodeVerifier{
		verifier:      voteVerifier,
		incomingTasks: make(chan pseudonodeTask, pseudonodeVerificationBacklog),
	}
	n.closeWg.Add(1)
	go pv.verifierLoop(&n)
	return pv
}

// makeProposals creates a slice of block proposals for the given round and period.
func (n asyncPseudonode) makeProposals(round round, period period, accounts []account.Participation) ([]proposal, []unauthenticatedVote) {
	deadline := time.Now().Add(config.ProposalAssemblyTime)
	ve, err := n.factory.AssembleBlock(round.number, deadline) // XXXX needs branch-aware
	if err != nil {
		if err != ErrAssembleBlockRoundStale {
			n.log.Errorf("pseudonode.makeProposals: could not generate a proposal for round %d: %v", round, err)
		}
		return nil, nil
	}

	votes := make([]unauthenticatedVote, 0, len(accounts))
	proposals := make([]proposal, 0, len(accounts))
	for _, account := range accounts {
		payload, proposal, err := proposalForBlock(account.Address(), account.VRFSecrets(), ve, period, n.ledger)
		if err != nil {
			n.log.Errorf("pseudonode.makeProposals: could not create proposal for block (address %v): %v", account.Address(), err)
			continue
		}

		// attempt to make the vote
		rv := rawVote{Sender: account.Address(), Round: round.number, Branch: round.branch, Period: period, Step: propose, Proposal: proposal}
		uv, err := makeVote(rv, account.VotingSigner(), account.VRFSecrets(), n.ledger)
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
func (n asyncPseudonode) makeVotes(round round, period period, step step, proposal proposalValue, participation []account.Participation) []unauthenticatedVote {
	votes := make([]unauthenticatedVote, 0)
	for _, account := range participation {
		rv := rawVote{Sender: account.Address(), Round: round.number, Branch: round.branch, Period: period, Step: step, Proposal: proposal}
		uv, err := makeVote(rv, account.VotingSigner(), account.VRFSecrets(), n.ledger)
		if err != nil {
			n.log.Warnf("pseudonode.makeVotes: could not create vote: %v", err)
			continue
		}
		votes = append(votes, uv)
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
		task.execute(pv.verifier, n.quit)
	}
}

// populateParticipationKeys refreshes the participation key cache ( as needed ), and updates the
// task with the loaded participation keys. It returns whether we have any participation keys
// for the given round.
func (t *pseudonodeBaseTask) populateParticipationKeys(r round) bool {
	t.participation = t.node.loadRoundParticipationKeys(r.number) // XXX likely OK to ignore branch?
	return len(t.participation) > 0
}

func (t pseudonodeBaseTask) outputChannel() chan externalEvent {
	return t.out
}

func (t pseudonodeBaseTask) close() {
	close(t.out)
}

func (t pseudonodeVotesTask) execute(verifier *AsyncVoteVerifier, quit chan struct{}) {
	defer t.close()

	// check to see if task already expired.
	if t.context.Err() != nil {
		return
	}

	unverifiedVotes := t.node.makeVotes(t.round, t.period, t.step, t.prop, t.participation)
	t.node.log.Infof("pseudonode: made %v votes", len(unverifiedVotes))
	results := make(chan asyncVerifyVoteResponse, len(unverifiedVotes))
	for i, uv := range unverifiedVotes {
		msg := message{Tag: protocol.AgreementVoteTag, UnauthenticatedVote: uv}
		verifier.verifyVote(context.TODO(), t.node.ledger, uv, i, msg, results)
	}

	orderedResults := make([]asyncVerifyVoteResponse, len(unverifiedVotes))
	for i := 0; i < len(unverifiedVotes); i++ {
		resp := <-results
		orderedResults[resp.index] = resp
	}
	var verifiedResults []asyncVerifyVoteResponse
	for _, resp := range orderedResults {
		if resp.err == nil {
			verifiedResults = append(verifiedResults, resp)
		}
	}

	var totalWeight uint64
	for _, result := range verifiedResults {
		totalWeight += result.v.Cred.Weight
	}
	if t.node.log.IsLevelEnabled(logging.Info) {
		for _, result := range verifiedResults {
			vote := result.v
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
			t.node.log.with(logEvent).Infof("vote created for broadcast (weight %d, total weight %d)", vote.Cred.Weight, totalWeight)
			if !t.node.log.GetTelemetryEnabled() {
				continue
			}
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
		t.node.log.Infof("pseudonode.makeVotes: %v votes created for %v at (%v, %v, %v), total weight %v", len(verifiedResults), t.prop, t.round, t.period, t.step, totalWeight)
	}
	if len(verifiedResults) > 0 {
		// wait until the persist state is flushed, as we don't want to send any vote unless we've completed flushing it to disk.
		// at this point, the error was already logged.
		select {
		case err, ok := <-t.persistStateDone:
			if ok && err != nil {
				// we were unable to persist to disk; dont sent any votes.
				t.node.log.Warnf("pseudonode.makeVotes: %v votes dropped due to disk persistence failuire : %v", len(verifiedResults), err)
				return
			}
		case <-quit:
			return
		case <-t.context.Done():
			// we done care about the output anymore; just exit.
			return
		}
	}

	for range verifiedResults {
		t.node.monitor.inc(pseudonodeCoserviceType)
	}
	t.node.monitor.dec(pseudonodeCoserviceType)

	// push results into channel.
	for _, r := range verifiedResults {
		select {
		case t.out <- messageEvent{T: voteVerified, Input: r.message, Err: makeSerErr(r.err)}:
		case <-quit:
			return
		case <-t.context.Done():
			// we done care about the output anymore; just exit.
			return
		}
	}
}

func (t pseudonodeProposalsTask) execute(verifier *AsyncVoteVerifier, quit chan struct{}) {
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

	results := make(chan asyncVerifyVoteResponse, len(votes))
	for i, uv := range votes {
		msg := message{Tag: protocol.AgreementVoteTag, UnauthenticatedVote: uv}
		verifier.verifyVote(context.TODO(), t.node.ledger, uv, i, msg, results)
	}

	cryptoOutputs := make([]asyncVerifyVoteResponse, len(votes))
	for i := 0; i < len(votes); i++ {
		resp := <-results
		cryptoOutputs[resp.index] = resp
	}

	var verifiedVotes []asyncVerifyVoteResponse
	var verifiedPayloads []proposal

	for i := range cryptoOutputs {
		if cryptoOutputs[i].err != nil {
			// this is normal and happens every time an account isn't self-selected for voting.
			continue
		}

		verifiedVotes = append(verifiedVotes, cryptoOutputs[i])
		verifiedPayloads = append(verifiedPayloads, payloads[i])

		vote := cryptoOutputs[i].v
		logEvent := logspec.AgreementEvent{
			Type:         logspec.ProposalBroadcast,
			Hash:         vote.R.Proposal.BlockDigest.String(),
			ObjectRound:  uint64(vote.R.Round),
			ObjectPeriod: uint64(vote.R.Period),
		}
		t.node.log.with(logEvent).Infof("pseudonode.makeProposals: proposal created for (%d, %d)", vote.R.Round, vote.R.Period)
		if t.node.log.GetTelemetryEnabled() {
			t.node.log.EventWithDetails(telemetryspec.Agreement, telemetryspec.BlockProposedEvent, telemetryspec.BlockProposedEventDetails{
				Hash:    vote.R.Proposal.BlockDigest.String(),
				Address: vote.R.Sender.String(),
				Round:   uint64(vote.R.Round),
				Period:  uint64(vote.R.Period),
			})
		}
	}
	t.node.log.Infof("pseudonode.makeProposals: %d proposals created for round %d, period %d", len(verifiedVotes), t.round, t.period)

	for range verifiedVotes {
		t.node.monitor.inc(pseudonodeCoserviceType)
	}
	for range verifiedPayloads {
		t.node.monitor.inc(pseudonodeCoserviceType)
	}
	t.node.monitor.dec(pseudonodeCoserviceType)

	// push results into channel.
	for _, r := range verifiedVotes {
		select {
		case t.out <- messageEvent{T: voteVerified, Input: r.message, Err: makeSerErr(r.err)}:
		case <-quit:
			return
		case <-t.context.Done():
			// we done care about the output anymore; just exit.
			return
		}
	}

	for _, payload := range verifiedPayloads {
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
