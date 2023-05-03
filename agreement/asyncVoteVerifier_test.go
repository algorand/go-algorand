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
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
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

// TestAsyncQuit stops the verifier while sending verification votes to it
// No results should be dropped. If any is dropped, avv.wg.Wait() will get stuck.
func TestAsyncQuit(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	errChan := make(chan error)
	ledger, votes, eqVotes, _, _ := generateTestVotes(false, errChan, 1, 1, 0.0)
	outChan := make(chan asyncVerifyVoteResponse, 4)

	// flush the output chan
	go func() {
		for range outChan {
		}
		return
	}()

	for x := 0; x < 100; x++ {
		voteVerifier := MakeStartAsyncVoteVerifier(nil)
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if x%2 == 0 {
					voteVerifier.verifyVote(context.Background(), ledger, *votes[0].uv, uint64(votes[0].id), message{}, outChan)
				} else {
					voteVerifier.verifyEqVote(context.Background(), ledger, *eqVotes[0].uev, uint64(votes[0].id), message{}, outChan)
				}
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

// TestAsyncQuitLong tests to make sure the AsyncVoteVerifier operates across service Shutdown/Start cycles
// Votes are sent to the verifier, then the verifier stopped, and all votes submitted should be accounted for
func TestAsyncQuitLong(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	errChan := make(chan error)
	count := 1000
	eqCount := 1000
	shutdownAt := (count + eqCount) / 10
	errProb := float32(0.5)
	sent := 0
	received := 0

	ledger, votes, eqVotes, errsV, errsEqv := generateTestVotes(false, errChan, count, eqCount, errProb)
	mainPool := execpool.MakePool(t)
	defer mainPool.Shutdown()
	voteVerifier := MakeStartAsyncVoteVerifier(nil)
	outChan := make(chan asyncVerifyVoteResponse, voteVerifier.Parallelism())

	wg := sync.WaitGroup{}
	wg.Add(2)

	noMore := make(chan struct{})

	// collect the verification results and check against the error expectation
	go func() {
		defer wg.Done()
		defer close(errChan)
		timeout := time.NewTicker(200 * time.Millisecond)
		defer timeout.Stop()
		for {
			select {
			case res := <-outChan:
				received++
				var expectedError error
				if res.req.uv != nil {
					expectedError = errsV[int(res.index)]
				} else {
					expectedError = errsEqv[int(res.index)]
				}
				if (expectedError == nil && res.err != nil) || (expectedError != nil && res.err == nil) {
					if !(received > shutdownAt &&
						(res.err == context.Canceled || res.err == execpool.ErrShuttingDownError)) {
						errChan <- fmt.Errorf("expected %v got %v", expectedError, res.err)
					}
				}
				if received == shutdownAt {
					go voteVerifier.Quit()
				}
				timeout.Reset(100 * time.Millisecond)

			case <-timeout.C:
				select {
				case <-noMore:
					if sent-received <= 1 {
						return
					}
				default:
				}
				timeout.Reset(100 * time.Millisecond)
			}
		}
	}()

	// stream the votes to the verifier
	go func() {
		defer wg.Done()
		defer close(noMore)
		vi := 0
		evi := 0
		for c := 0; c < count+eqCount; c++ {
			// pick a vote if there are votes, and if either there are no eqVotes or the relative prob
			turnVote := len(votes) > 0 && (len(eqVotes) == 0 || rand.Float32() < (float32(count)/float32(count+eqCount)))
			if turnVote {
				uv := votes[vi%count]
				vi++
				voteVerifier.verifyVote(context.Background(), ledger, *uv.uv, uint64(uv.id), message{}, outChan)
			} else {
				uev := eqVotes[evi%eqCount]
				evi++
				voteVerifier.verifyEqVote(context.Background(), ledger, *uev.uev, uint64(uev.id), message{}, outChan)
			}
			// If the ctx is done, we cannot know for sure if the vote was accepted or ignored. But can be sure that all votes
			// before this were accepted, and all votes afterwards will be ignored.
			select {
			case <-voteVerifier.ctx.Done():
				return
			default:
				sent++
			}
		}
	}()
	// monitor the errors returned from the various goroutines
	for err := range errChan {
		require.NoError(t, err)
	}
	wg.Wait()
	// Since cannot be sure about the last vote when the ctx was done, we allow a difference of 1
	require.Less(t, sent-received, 1)

}

func makeTestService(ledger Ledger, t *testing.T) (*Service, error) {
	accounts, _ := createTestAccountsAndBalances(t, 1, (&[32]byte{})[:])
	keys := makeRecordingKeyManager(accounts)
	accessor, err := db.MakeAccessor(t.Name()+"_crash.db", false, true)
	if err != nil {
		return nil, err
	}
	clock := makeTestingClock(nil)
	endpoint := testingNetworkEndpoint{}
	params := Parameters{
		Logger:       logging.Base(),
		Network:      &endpoint,
		Accessor:     accessor,
		Ledger:       ledger, // makeTestLedger(readOnlyGenesis10),
		BlockFactory: testBlockFactory{Owner: 1},
		KeyManager:   keys,
		Clock:        clock,
	}
	return MakeService(params)
}
