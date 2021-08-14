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
	"sync"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// TODO put these in config
const (
	voteParallelism     = 16
	proposalParallelism = 4
	bundleParallelism   = 2
)

type (
	// A cryptoVerifier is used to parallelize the cryptographic verification of votes, proposals, and bundles.
	//
	// Callers submit cryptoRequests into the verifier using cryptoVerifier.Verify*
	// and obtain results using cryptoVerifier.Verified*.
	//
	// cryptoVerifier.Verify* will block if the cryptoVerifier is at capacity and cannot accept more requests.
	// If no goroutine is dequeuing cryptoResults from cryptoVerifier.Verified*, deadlock could occur.
	// To avoid this scenario, callers should call cryptoVerifier.ChannelFull to back off from submitting requests.
	cryptoVerifier interface {
		// VerifyVote enqueues the request to be verified.
		//
		// The passed-in context ctx may be used to cancel the enqueuing request.
		VerifyVote(ctx context.Context, request cryptoVoteRequest)

		// VerifyProposal enqueues the request to be verified.
		//
		// The passed-in context ctx may be used to cancel the enqueuing request.
		VerifyProposal(ctx context.Context, request cryptoProposalRequest)

		// VerifyBundle enqueues the request to be verified.
		//
		// The passed-in context ctx may be used to cancel the enqueuing request.
		VerifyBundle(ctx context.Context, request cryptoBundleRequest)

		// Verified returns a channel which contains verification results.
		//
		// The type of results returned depends on the given tag.
		//  - If tag = protocol.ProposalPayloadTag, the results are of type proposalPayload.
		//  - If tag = protocol.VoteBundleTag, the results are of type bundle.
		//
		// If verification has failed, the conversion from an unauthenticated to an authenticate type does not occur,
		// and instead cryptoResult.Err is set.
		//
		// VerifiedVote is like Verified but for votes.
		Verified(tag protocol.Tag) <-chan cryptoResult
		VerifiedVotes() <-chan asyncVerifyVoteResponse

		// ChannelFull determines if the input channel for a given tag is currently full.
		//
		// The tag here corresponds to the tags in cryptoVerifier.Verified.
		ChannelFull(tag protocol.Tag) bool

		// Quit shuts down the verifier goroutines.
		Quit()
	}

	cryptoVoteRequest struct {
		message                   // the message we would like to verify.
		TaskIndex int             // Caller specific number that would be passed back in the asyncVerifyVoteResponse.TaskIndex field
		Round     round           // The round that we're going to test against.
		Period    period          // The period associated with the message we're going to test.
		ctx       context.Context // A context for this request, if the context is cancelled then the request is stale.
	}

	cryptoProposalRequest struct {
		message                   // the message we would like to verify.
		TaskIndex int             // Caller specific number that would be passed back in the cryptoResult.TaskIndex field
		Round     round           // The round that we're going to test against.
		Period    period          // The period associated with the message we're going to test.
		Pinned    bool            // A flag that is set if this is a pinned value for the given round.
		ctx       context.Context // A context for this request, if the context is cancelled then the request is stale.
	}

	cryptoBundleRequest struct {
		message                   // the message we would like to verify.
		TaskIndex int             // Caller specific number that would be passed back in the asyncVerifyVoteResponse.TaskIndex field
		Round     round           // The round that we're going to test against.
		Period    period          // The period associated with the message we're going to test.
		Certify   bool            // A flag that set if this is a cert bundle.
		ctx       context.Context // A context for this request, if the context is cancelled then the request is stale.
	}

	cryptoResult struct {
		message
		Err       serializableError
		TaskIndex int  // the TaskIndex that was passed to the cryptoVerifier during the Verify call on the cryptoRequest.TaskIndex
		Cancelled bool // whether the corresponding request was cancelled before verification completed
	}

	// A poolCryptoVerifier uses asynchronous goroutines to implement cryptoVerifier.
	poolCryptoVerifier struct {
		voteVerifier *AsyncVoteVerifier
		votes        voteChanPair
		proposals    proposalChanPair
		bundles      bundleChanPair

		validator        BlockValidator
		ledger           LedgerReader
		proposalContexts pendingRequestsContext
		log              logging.Logger

		quit chan struct{}
		wg   sync.WaitGroup
	}

	voteChanPair struct {
		in  chan cryptoVoteRequest
		out chan asyncVerifyVoteResponse
	}

	proposalChanPair struct {
		in  chan cryptoProposalRequest
		out chan cryptoResult
	}

	bundleChanPair struct {
		in  chan cryptoBundleRequest
		out chan cryptoResult
	}

	bundleFuture struct {
		message
		index int
		wait  func() (bundle, error)
		ctx   context.Context
	}
)

func makeCryptoVerifier(l LedgerReader, v BlockValidator, voteVerifier *AsyncVoteVerifier, logger logging.Logger) cryptoVerifier {
	c := &poolCryptoVerifier{
		ledger:           l,
		validator:        v,
		proposalContexts: makePendingRequestsContext(),
		quit:             make(chan struct{}),
	}
	c.votes = voteChanPair{
		in:  make(chan cryptoVoteRequest, voteVerifier.Parallelism()),
		out: make(chan asyncVerifyVoteResponse, 3*voteVerifier.Parallelism()),
	}
	c.bundles = bundleChanPair{
		in:  make(chan cryptoBundleRequest, 1),
		out: make(chan cryptoResult, 3),
	}

	// Allocate enough outbound space to absorb one proposal per pending vote.
	// TODO We want proper backpressure from the proposalTable into the network.
	baseBuffer := 3
	maxVotes := cap(c.votes.in) + cap(c.votes.out) + voteVerifier.Parallelism()
	c.proposals = proposalChanPair{
		in:  make(chan cryptoProposalRequest, 1),
		out: make(chan cryptoResult, maxVotes+baseBuffer),
	}

	c.wg.Add(3)

	bundleFutures := make(chan bundleFuture)
	go c.voteFillWorker(bundleFutures)
	go c.bundleWaitWorker(bundleFutures)
	go c.proposalVerifyWorker()

	c.voteVerifier = voteVerifier
	c.log = logger
	return c
}

func (c *poolCryptoVerifier) voteFillWorker(toBundleWait chan<- bundleFuture) {
	votesin := c.votes.in
	bundlesin := c.bundles.in
	defer close(toBundleWait)
	defer c.wg.Done()

	for {
		select {
		case votereq, ok := <-votesin:
			if !ok {
				votesin = nil
				if bundlesin == nil {
					return
				}
				continue
			}

			uv := votereq.message.UnauthenticatedVote
			c.voteVerifier.verifyVote(votereq.ctx, c.ledger, uv, votereq.TaskIndex, votereq.message, c.votes.out)
		case bundlereq, ok := <-bundlesin:
			if !ok {
				bundlesin = nil
				if votesin == nil {
					return
				}
				continue
			}

			// this sends messages down c.voteVerifier
			fn := bundlereq.message.UnauthenticatedBundle.verifyAsync(bundlereq.ctx, c.ledger, c.voteVerifier)
			future := bundleFuture{
				message: bundlereq.message,
				index:   bundlereq.TaskIndex,
				wait:    fn,
				ctx:     bundlereq.ctx,
			}
			select {
			case toBundleWait <- future:
			case <-c.quit:
				return
			}
		case <-c.quit:
			return
		}
	}
}

func (c *poolCryptoVerifier) bundleWaitWorker(fromVoteFill <-chan bundleFuture) {
	defer c.wg.Done()
	for future := range fromVoteFill {
		b, err := future.wait()
		res := cryptoResult{
			message:   future.message,
			TaskIndex: future.index,
		}
		if err != nil {
			res.Err = makeSerErr(err)
			select {
			case <-future.ctx.Done():
				res.Cancelled = true
			default:
			}
		} else {
			res.Bundle = b
		}

		select {
		case c.bundles.out <- res:
		case <-c.quit:
			return
		}
	}
}

func (c *poolCryptoVerifier) VerifyVote(ctx context.Context, request cryptoVoteRequest) {
	c.proposalContexts.clearStaleContexts(request.Round, request.Period, false, false)
	request.ctx = c.proposalContexts.addVote(request)
	switch request.Tag {
	case protocol.AgreementVoteTag:
		select {
		case c.votes.in <- request:
		case <-ctx.Done():
		}
	default:
		logging.Base().Panicf("Verify action called on bad type: request is %v", request)
	}
}

func (c *poolCryptoVerifier) VerifyProposal(ctx context.Context, request cryptoProposalRequest) {
	c.proposalContexts.clearStaleContexts(request.Round, request.Period, request.Pinned, false)
	request.ctx = c.proposalContexts.addProposal(request)
	switch request.Tag {
	case protocol.ProposalPayloadTag:
		select {
		case c.proposals.in <- request:
		case <-ctx.Done():
		}
	default:
		logging.Base().Panicf("Verify action called on bad type: request is %v", request)
	}
}

func (c *poolCryptoVerifier) VerifyBundle(ctx context.Context, request cryptoBundleRequest) {
	c.proposalContexts.clearStaleContexts(request.Round, request.Period, false, request.Certify)
	request.ctx = c.proposalContexts.addBundle(request)
	switch request.Tag {
	case protocol.VoteBundleTag:
		select {
		case c.bundles.in <- request:
		case <-ctx.Done():
		}
	default:
		logging.Base().Panicf("Verify action called on bad type: request is %v", request)
	}
}

func (c *poolCryptoVerifier) Verified(tag protocol.Tag) <-chan cryptoResult {
	switch tag {
	case protocol.ProposalPayloadTag:
		return c.proposals.out
	case protocol.VoteBundleTag:
		return c.bundles.out
	default:
		logging.Base().Panicf("Verified called on bad type: %v", tag)
		return nil
	}
}

func (c *poolCryptoVerifier) VerifiedVotes() <-chan asyncVerifyVoteResponse {
	return c.votes.out
}

func (c *poolCryptoVerifier) ChannelFull(tag protocol.Tag) (ret bool) {
	switch tag {
	// 1. can we enqueue another message?
	// 2. is there capacity to absorb all pending requests?
	// (for deadlock safety, upper-bound the number of pending requests)
	case protocol.ProposalPayloadTag:
		return len(c.proposals.in) == cap(c.proposals.in) || len(c.proposals.out) > 1 // TODO we want proper backpressue from the proposalTable eventually
	case protocol.AgreementVoteTag:
		return len(c.votes.in) == cap(c.votes.in) || cap(c.votes.out)-len(c.votes.out) < c.voteVerifier.Parallelism()+len(c.votes.in)
	case protocol.VoteBundleTag:
		return len(c.bundles.in) == cap(c.bundles.in) || cap(c.bundles.out)-len(c.bundles.out) < 2
	default:
		logging.Base().Panicf("ChannelFull called on bad type: %v", tag)
		return false
	}
}

func (c *poolCryptoVerifier) Quit() {
	close(c.quit)
	close(c.votes.in)
	close(c.bundles.in)
	close(c.proposals.in)
	c.wg.Wait()
}

func (c *poolCryptoVerifier) proposalVerifyWorker() {
	defer c.wg.Done()
	for req := range c.proposals.in {
		select {
		case c.proposals.out <- c.verifyProposalPayload(req):
		case <-c.quit:
			return
		}
	}
}

func (c *poolCryptoVerifier) verifyProposalPayload(request cryptoProposalRequest) cryptoResult {
	m := request.message
	up := request.UnauthenticatedProposal

	p, err := up.validate(request.ctx, request.Round, c.ledger, c.validator)
	select {
	case <-request.ctx.Done():
		m.Proposal = p
		return cryptoResult{message: m, TaskIndex: request.TaskIndex, Err: makeSerErr(request.ctx.Err()), Cancelled: true}
	default:
	}

	if err != nil {
		err := makeSerErrf("rejected invalid proposalPayload: %v", err)
		return cryptoResult{message: m, Err: err, TaskIndex: request.TaskIndex}
	}

	m.Proposal = p
	return cryptoResult{message: m, TaskIndex: request.TaskIndex}
}
