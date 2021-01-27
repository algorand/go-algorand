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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
)

// unauthenticatedBundle is a bundle which has not yet been verified.
type unauthenticatedBundle struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Round    basics.Round  `codec:"rnd"`
	Period   period        `codec:"per"`
	Step     step          `codec:"step"`
	Proposal proposalValue `codec:"prop"`

	Votes             []voteAuthenticator             `codec:"vote,allocbound=config.MaxVoteThreshold"`
	EquivocationVotes []equivocationVoteAuthenticator `codec:"eqv,allocbound=config.MaxVoteThreshold"`
}

// bundle is a set of votes, all from the same round, period, and step, and from distinct senders, that reaches quorum.
//
// It also include equivocation pairs -- pairs of votes where someone maliciously voted for two different values -- as these count as votes for *any* value.
type bundle struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	U unauthenticatedBundle `codec:"u"`

	Votes             []vote             `codec:"vote,allocbound=config.MaxVoteThreshold"`
	EquivocationVotes []equivocationVote `codec:"eqv,allocbound=config.MaxVoteThreshold"`
}

// voteAuthenticators omit the Round, Period, Step, and Proposal for compression
// and to simplify checking logic.
type voteAuthenticator struct {
	_struct struct{} `codec:""` // not omitempty

	Sender basics.Address                      `codec:"snd"`
	Cred   committee.UnauthenticatedCredential `codec:"cred"`
	Sig    crypto.OneTimeSignature             `codec:"sig,omitempty,omitemptycheckstruct"`
}

type equivocationVoteAuthenticator struct {
	_struct struct{} `codec:""` // not omitempty

	Sender    basics.Address                      `codec:"snd"`
	Cred      committee.UnauthenticatedCredential `codec:"cred"`
	Sigs      [2]crypto.OneTimeSignature          `codec:"sig,omitempty,omitemptycheckstruct"`
	Proposals [2]proposalValue                    `codec:"props"`
}

// makeBundle takes in the votes from a round and produces a bundle that proves the vote is accurate.
// Precondition: The passed-in votes are assumed to all be distinct, valid votes for the same block in the same round, perid, and step.
func makeBundle(proto config.ConsensusParams, targetProposal proposalValue, votes []vote, equivocationVotes []equivocationVote) unauthenticatedBundle {
	if len(votes) == 0 {
		logging.Base().Panicf("makeBundle: no votes present in bundle (len(equivocationVotes) = %v)", len(equivocationVotes))
	}

	// Bundle the relevant votes into a bundle
	// (note that all of these votes are valid but aren't necessarily all for the same block or in the same step)
	// (eventually we'll also include balance proofs for each voter)
	certVotes := make([]voteAuthenticator, 0)
	packedSoFar := uint64(0)
	step := votes[0].R.Step
	for _, vote := range votes {
		if vote.R.Proposal != targetProposal {
			logging.Base().Panicf("makeBundle: invalid vote passed into function: expected proposal-value %v but got %v", targetProposal, vote.R.Proposal)
		}
	}

	for _, vote := range votes {
		if step.reachesQuorum(proto, packedSoFar) {
			break
		}

		u := vote.u()
		auth := voteAuthenticator{
			Sender: u.R.Sender,
			Cred:   u.Cred,
			Sig:    vote.Sig,
		}
		certVotes = append(certVotes, auth)
		packedSoFar += vote.Cred.Weight
	}

	certEquiVotes := make([]equivocationVoteAuthenticator, 0)
	for _, ev := range equivocationVotes {
		if step.reachesQuorum(proto, packedSoFar) {
			break
		}
		auth := equivocationVoteAuthenticator{
			Sender:    ev.Sender,
			Cred:      ev.Cred.UnauthenticatedCredential,
			Sigs:      ev.Sigs,
			Proposals: ev.Proposals,
		}
		certEquiVotes = append(certEquiVotes, auth)
		packedSoFar += ev.Cred.Weight
	}

	if !step.reachesQuorum(proto, packedSoFar) {
		logging.Base().Panicf("not enough votes to generate bundle for %+v: have %v < %v", targetProposal, packedSoFar, step.committeeSize(proto))
	}

	return unauthenticatedBundle{
		Round:             votes[0].R.Round,
		Period:            votes[0].R.Period,
		Step:              votes[0].R.Step,
		Proposal:          targetProposal,
		Votes:             certVotes,
		EquivocationVotes: certEquiVotes,
	}
}

// verify checks that the bundle is valid, i.e.:
//
// - all the votes in the bundle are valid
// - the senders of the votes are distinct and form a full, valid committee
func (b unauthenticatedBundle) verify(ctx context.Context, l LedgerReader, avv *AsyncVoteVerifier) (bundle, error) {
	return b.verifyAsync(ctx, l, avv)()
}

// verifyAsync verifies a bundle in the background, returning a future
// which contains the result of verification.
func (b unauthenticatedBundle) verifyAsync(ctx context.Context, l LedgerReader, avv *AsyncVoteVerifier) func() (bundle, error) {
	// termErrorFn creates a future that immediately returns with an error.
	termErrorFn := func(err error) func() (bundle, error) {
		return func() (bundle, error) {
			return bundle{}, err
		}
	}

	// termFmtErrorFn is like termErrorFn but runs fmt.Errorf on its input.
	termFmtErrorFn := func(format string, a ...interface{}) func() (bundle, error) {
		return func() (bundle, error) {
			return bundle{}, fmt.Errorf(format, a...)
		}
	}

	if b.Step == propose {
		return termFmtErrorFn("unauthenticatedBundle.verify: b.Step = %v", propose)
	}

	proto, err := l.ConsensusParams(ParamsRound(b.Round))
	if err != nil {
		return termFmtErrorFn("unauthenticatedBundle.verify: could not get consensus params for round %d: %v", ParamsRound(b.Round), err)
	}

	numVotes := uint64(len(b.Votes))
	numEquivocationVotes := uint64(len(b.EquivocationVotes))
	if numVotes > b.Step.threshold(proto) || numEquivocationVotes > b.Step.threshold(proto) || numVotes+numEquivocationVotes > b.Step.threshold(proto) {
		return termFmtErrorFn("unauthenticatedBundle.verify: bundle too large: len(b.Votes) = %v, len(b.EquivocationVotes) = %v; step threshold = %v", numVotes, numEquivocationVotes, b.Step.threshold(proto))
	}

	// check for duplicated votes
	voters := make(map[basics.Address]bool)
	for _, v := range b.Votes {
		if voters[v.Sender] {
			return termFmtErrorFn("unauthenticatedBundle.verify: vote %+v was duplicated in bundle", v)
		}
		voters[v.Sender] = true
	}
	for _, ev := range b.EquivocationVotes {
		if voters[ev.Sender] {
			return termFmtErrorFn("unauthenticatedBundle.verify: equivocating vote pair %+v was duplicated in bundle", ev)
		}
		voters[ev.Sender] = true
	}

	// make a buffer large enough to queue all results so we never wait
	results := make(chan asyncVerifyVoteResponse, len(b.Votes)+len(b.EquivocationVotes))

	// create verification requests for votes
	for i, auth := range b.Votes {
		select {
		case <-ctx.Done():
			return termErrorFn(ctx.Err())
		default:
		}

		rv := rawVote{Sender: auth.Sender, Round: b.Round, Period: b.Period, Step: b.Step, Proposal: b.Proposal}
		uv := unauthenticatedVote{R: rv, Cred: auth.Cred, Sig: auth.Sig}
		avv.verifyVote(ctx, l, uv, i, message{}, results)
	}

	// create verification requests for equivocation votes
	for i, auth := range b.EquivocationVotes {
		select {
		case <-ctx.Done():
			return termErrorFn(ctx.Err())
		default:
		}

		uev := unauthenticatedEquivocationVote{
			Sender:    auth.Sender,
			Round:     b.Round,
			Period:    b.Period,
			Step:      b.Step,
			Cred:      auth.Cred,
			Proposals: auth.Proposals,
			Sigs:      auth.Sigs,
		}
		avv.verifyEqVote(ctx, l, uev, i, message{}, results)
	}

	return func() (bundle, error) {
		var votes []vote
		var eqVotes []equivocationVote
		var weight uint64 // total weight

		// read the results as they come
		for i := 0; i < len(b.Votes)+len(b.EquivocationVotes); i++ {
			select {
			case res := <-results:
				isEquivocationVote := false
				if res.ev != (equivocationVote{}) {
					isEquivocationVote = true
				}

				if res.err != nil {
					if isEquivocationVote {
						return bundle{}, fmt.Errorf("unauthenticatedBundle.verify: equivocating vote pair %+v (index %v) was invalid in bundle: %v", res.ev, res.index, res.err)
					}
					return bundle{}, fmt.Errorf("unauthenticatedBundle.verify: vote %+v (index %v) was invalid in bundle: %v", res.v, res.index, res.err)
				}

				if isEquivocationVote {
					weight += res.ev.Cred.Weight
					eqVotes = append(eqVotes, res.ev)
				} else {
					weight += res.v.Cred.Weight
					votes = append(votes, res.v)
				}
			case <-ctx.Done():
				return bundle{}, ctx.Err()
			}
		}

		if !b.Step.reachesQuorum(proto, weight) {
			return bundle{}, fmt.Errorf("bundle: did not see enough votes: %v < %v", weight, b.Step.committeeSize(proto))
		}

		return bundle{
			U: b,

			Votes:             votes,
			EquivocationVotes: eqVotes,
		}, nil
	}
}

func (b unauthenticatedBundle) Certificate() Certificate {
	if b.Step != cert {
		logging.Base().Panicf("bundle.Certificate: expected step=cert but got step=%v", b.Step)
	}
	if b.Proposal == bottom {
		logging.Base().Panicf("bundle.Certificate: attempted to generate a Certificate for a bottom-bundle")
	}
	return Certificate(b)
}

func (b bundle) u() unauthenticatedBundle {
	return b.U
}
