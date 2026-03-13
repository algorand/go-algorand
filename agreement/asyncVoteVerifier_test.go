// Copyright (C) 2019-2026 Algorand, Inc.
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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
)

type expiredExecPool struct {
	execpool.ExecutionPool
}

func (fp *expiredExecPool) EnqueueBacklog(enqueueCtx context.Context, t execpool.ExecFunc, arg interface{}, out chan interface{}) error {
	// generate an error, to see if we correctly report that on the verifyVote() call.
	return context.Canceled
}
func (fp *expiredExecPool) BufferSize() (length, capacity int) {
	return
}

// Test async vote verifier against a full execution pool.
func TestVerificationAgainstFullExecutionPool(t *testing.T) {
	partitiontest.PartitionTest(t)
	mainPool := execpool.MakePool(t)
	defer mainPool.Shutdown()

	voteVerifier := MakeAsyncVoteVerifier(&expiredExecPool{mainPool})
	defer voteVerifier.Quit()
	verifyErr := voteVerifier.verifyVote(context.Background(), nil, unauthenticatedVote{}, 0, message{}, make(chan<- asyncVerifyVoteResponse, 1))
	require.Equal(t, context.Canceled, verifyErr)
	verifyEqVoteErr := voteVerifier.verifyEqVote(context.Background(), nil, unauthenticatedEquivocationVote{}, 0, message{}, make(chan<- asyncVerifyVoteResponse, 1))
	require.Equal(t, context.Canceled, verifyEqVoteErr)
}

// bypassAsyncVoteVerifierCtxCheck is used to call the quivalent of AsyncVoteVerifier.verifyVote and to simulate the case
// where the ctx is checked in verifyVote before it is cancled. This likelihood is enhanced by the sleep of 10 ms.
// This behavior is possible, since the ctx is canceled from a different go-routine.
// bypassAsyncVoteVerifierCtxCheck is important to test what happens when the service shuts down, and a vote sneaks
// through the ctx check.
func bypassAsyncVoteVerifierCtxCheck(verctx context.Context, avv *AsyncVoteVerifier, l LedgerReader,
	uv unauthenticatedVote, index uint64, message message, out chan<- asyncVerifyVoteResponse) {
	avv.enqueueMu.RLock()
	defer avv.enqueueMu.RUnlock()
	select {
	case <-avv.ctx.Done(): // if we're quitting, don't enqueue the request
	// case <-verctx.Done(): DO NOT DO THIS! otherwise we will lose the vote (and forget to clean up)!
	// instead, enqueue so the worker will set the error value and return the cancelled vote properly.
	default:
		time.Sleep(10 * time.Millisecond)
		req := asyncVerifyVoteRequest{ctx: verctx, l: l, uv: &uv, index: index, message: message, out: out}
		avv.wg.Add(1)
		if err := avv.backlogExecPool.EnqueueBacklog(avv.ctx, avv.executeVoteVerification, req, avv.execpoolOut); err != nil {
			// we want to call "wg.Done()" here to "fix" the accounting of the number of pending tasks.
			// if we got a non-nil, it means that our context has expired, which means that we won't see this task
			// getting to the verification function.
			avv.wg.Done()
		}
	}
}

// TestServiceStop tests what happens when the agreement service shuts down, and
// calls the AsyncVoteVerifier Quit
// Specifically, tests the case when a vote gets submitted to the pool for verification
// concurrently when the verifier is quitting
func TestServiceStop(t *testing.T) {
	partitiontest.PartitionTest(t)
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	proposal := proposalValue{BlockDigest: randomBlockHash()}
	proposal.OriginalProposer = addresses[0]

	rv := rawVote{Sender: addresses[0], Round: 1, Period: 1, Step: step(0), Proposal: proposal}
	uv, err := makeVote(rv, otSecrets[0], vrfSecrets[0], ledger)
	require.NoError(t, err)
	outChan := make(chan asyncVerifyVoteResponse, 4)

	// flush the output chan
	go func() {
		for range outChan {
		}
		return
	}()
	for x := 0; x < 1000; x++ {
		voteVerifier := MakeAsyncVoteVerifier(execpool.MakeBacklog(nil, 0, execpool.HighPriority, nil))
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				bypassAsyncVoteVerifierCtxCheck(context.Background(), voteVerifier, ledger, uv, 1, message{}, outChan)
				select {
				case <-voteVerifier.workerWaitCh:
					return
				default:
				}
			}
		}()
		voteVerifier.Quit()
		wg.Wait()
	}
}
