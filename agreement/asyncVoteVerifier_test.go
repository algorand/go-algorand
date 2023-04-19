// Copyright (C) 2019-2023 Algorand, Inc.
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
	"math/rand"
	"sync"
	"testing"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/stretchr/testify/require"
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

func TestVerificationAgainstFullExecutionPool(t *testing.T) {
	partitiontest.PartitionTest(t)

	// do not print the error messages
	logging.Base().SetLevel(logging.Panic)

	mainPool := execpool.MakePool(t)
	defer mainPool.Shutdown()

	voteVerifier := MakeStartAsyncVoteVerifier(&expiredExecPool{mainPool})
	defer voteVerifier.Quit()

	outChan := make(chan asyncVerifyVoteResponse, 1)
	voteVerifier.verifyVote(context.Background(), nil, unauthenticatedVote{}, 0, message{}, outChan)
	response := <-outChan
	require.Equal(t, context.Canceled, response.err)
	require.True(t, response.cancelled)

	voteVerifier.verifyEqVote(context.Background(), nil, unauthenticatedEquivocationVote{}, 0, message{}, outChan)
	response = <-outChan
	require.Equal(t, context.Canceled, response.err)
	require.True(t, response.cancelled)
}

// TestAsyncVerificationVotes creates MakeStartAsyncVoteVerifier,
// sends Votes (50% valid) for verification, and checks the results
func TestAsyncVerificationVotes(t *testing.T) {
	partitiontest.PartitionTest(t)
	errProb := float32(0.5)
	numVotes := 200
	numEqVotes := 0
	sendReceiveVoteVerifications(false, errProb, numVotes, numEqVotes, t)
}

// TestAsyncVerificationEqVotes creates MakeStartAsyncVoteVerifier,
// sends EqVotes (50% valid) for verification, and checks the results
func TestAsyncVerificationEqVotes(t *testing.T) {
	partitiontest.PartitionTest(t)
	errProb := float32(0.5)
	numVotes := 0
	numEqVotes := 200
	sendReceiveVoteVerifications(false, errProb, numVotes, numEqVotes, t)
}

// TestAsyncVerification creates MakeStartAsyncVoteVerifier, sends
// Votes and EqVotes (50% valid) for verification, and checks the results
func TestAsyncVerification(t *testing.T) {
	partitiontest.PartitionTest(t)
	errProb := float32(0.5)
	numVotes := 200
	numEqVotes := 200
	sendReceiveVoteVerifications(false, errProb, numVotes, numEqVotes, t)
}

// BenchmarkAsyncVerification benchmarks the performance of verifying votes using MakeStartAsyncVoteVerifier
// with varying vote validity rates. Sends votes and eqVotes.
func BenchmarkAsyncVerification(b *testing.B) {
	errProbs := []float32{0.0, 0.2, 0.8}
	for _, errProb := range errProbs {
		b.Run(fmt.Sprintf("errProb_%.3f_any_err", errProb), func(b *testing.B) {
			sendReceiveVoteVerifications(false, errProb, b.N/2, b.N/2, b)
		})
		if errProb > float32(0.0) {
			b.Run(fmt.Sprintf("errProb_%.3f_sig_err_only", errProb), func(b *testing.B) {
				sendReceiveVoteVerifications(true, errProb, b.N/2, b.N/2, b)
			})
		}
	}
}

// BenchmarkAsyncVerificationVotes benchmarks the performance of verifying votes using MakeStartAsyncVoteVerifier
// with varying vote validity rates. Sends only votes.
func BenchmarkAsyncVerificationVotes(b *testing.B) {
	errProbs := []float32{0.0, 0.2, 0.8}
	for _, errProb := range errProbs {
		b.Run(fmt.Sprintf("errProb_%.3f_any_err", errProb), func(b *testing.B) {
			sendReceiveVoteVerifications(false, errProb, b.N, 0, b)
		})
		if errProb > float32(0.0) {
			b.Run(fmt.Sprintf("errProb_%.3f_sig_err_only", errProb), func(b *testing.B) {
				sendReceiveVoteVerifications(true, errProb, b.N, 0, b)
			})
		}
	}
}

// BenchmarkAsyncVerificationEqVotes benchmarks the performance of verifying votes using MakeStartAsyncVoteVerifier
// with varying vote validity rates. Sends only eqVotes.
func BenchmarkAsyncVerificationEqVotes(b *testing.B) {
	errProbs := []float32{0.0, 0.2, 0.8}
	for _, errProb := range errProbs {
		b.Run(fmt.Sprintf("errProb_%.3f_any_err", errProb), func(b *testing.B) {
			sendReceiveVoteVerifications(false, errProb, 0, b.N, b)
		})
		if errProb > float32(0.0) {
			b.Run(fmt.Sprintf("errProb_%.3f_sig_err_only", errProb), func(b *testing.B) {
				sendReceiveVoteVerifications(true, errProb, 0, b.N, b)
			})
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sendReceiveVoteVerifications(badSigOnly bool, errProb float32, count, eqCount int, tb testing.TB) {
	if count+eqCount < 10 {
		return
	}
	voteVerifier := MakeStartAsyncVoteVerifier(nil)
	defer voteVerifier.Quit()

	outChan := make(chan asyncVerifyVoteResponse, voteVerifier.Parallelism())
	gCount := min(200, count)
	gEqCount := min(200, eqCount)

	errChan := make(chan error)
	ledger, votes, eqVotes, errsV, errsEqv := generateTestVotes(badSigOnly, errChan, gCount, gEqCount, errProb)

	wg := sync.WaitGroup{}
	wg.Add(2)
	if b, ok := tb.(*testing.B); ok {
		b.ResetTimer()
	}
	// collect the verification results and check against the error expectation
	go func() {
		defer wg.Done()
		c := 0
		for res := range outChan {
			c++
			var expectedError error
			if res.req.uv != nil {
				expectedError = errsV[int(res.index)]
			} else {
				expectedError = errsEqv[int(res.index)]
			}
			if (expectedError == nil && res.err != nil) || (expectedError != nil && res.err == nil) {
				errChan <- fmt.Errorf("expected %v got %v", expectedError, res.err)
			}
			if c == count+eqCount {
				break
			}
		}
		close(errChan)
	}()
	// stream the votes to the verifier
	go func() {
		defer wg.Done()
		vi := 0
		evi := 0
		for c := 0; c < count+eqCount; c++ {
			// pick a vote if there are votes, and if either there are no eqVotes or the relative prob
			turnVote := len(votes) > 0 && (len(eqVotes) == 0 || rand.Float32() < (float32(count)/float32(count+eqCount)))
			if turnVote {
				uv := votes[vi%gCount]
				vi++
				voteVerifier.verifyVote(context.Background(), ledger, *uv.uv, uint64(uv.id), message{}, outChan)
			} else {
				uev := eqVotes[evi%gEqCount]
				evi++
				voteVerifier.verifyEqVote(context.Background(), ledger, *uev.uev, uint64(uev.id), message{}, outChan)
			}
		}
	}()
	// monitor the errors returned from the various goroutines
	for err := range errChan {
		require.NoError(tb, err)
	}
	wg.Wait()
}
func generateTestVotes(onlyBadSigs bool, errChan chan<- error, count, eqCount int, errProb float32) (ledger Ledger,
	votes []*unVoteTest, eqVotes []*unEqVoteTest, errsV, errsEqv map[int]error) {
	votes = make([]*unVoteTest, count)
	eqVotes = make([]*unEqVoteTest, eqCount)
	errsV = make(map[int]error)
	errsEqv = make(map[int]error)
	wg := sync.WaitGroup{}
	vg := makeTestVoteGenerator()

	nextErrType := 0
	for c := 0; c < count; c++ {
		errType := validVote
		if rand.Float32() < errProb {
			if onlyBadSigs {
				errType = 0
			} else {
				errType = nextErrType
				nextErrType = (nextErrType + 1) % (vg.invalidVoteOptions() - 1)
			}
		}
		v, err := vg.getTestVote(errType)
		if err != nil {
			errChan <- fmt.Errorf("failed to generate a vote")
		}
		errsV[v.id] = v.err
		votes[v.id] = v
	}

	nextErrType = 0
	vg.counter = 0
	for c := 0; c < eqCount; c++ {
		errType := validVote
		if rand.Float32() < errProb {
			if onlyBadSigs {
				errType = 0
			} else {
				errType = nextErrType
				nextErrType = (nextErrType + 1) % (vg.invalidEqVoteOptions() - 1)
			}
		}
		v, err := vg.getTestEqVote(errType)
		if err != nil {
			errChan <- fmt.Errorf("failed to generate a vote")
		}
		errsEqv[v.id] = v.err
		eqVotes[v.id] = v
	}
	wg.Wait()
	return vg.ledger, votes, eqVotes, errsV, errsEqv
}
