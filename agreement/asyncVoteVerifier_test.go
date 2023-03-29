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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
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

// Test async vote verifier against a canceled execution pool.
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

// Test async vote verifier
func TestAsyncVerification(t *testing.T) {
	partitiontest.PartitionTest(t)

	voteVerifier := MakeStartAsyncVoteVerifier(nil)
	defer voteVerifier.Quit()

	outChan := make(chan asyncVerifyVoteResponse, 1)

	uvChan := make(chan *unVoteTest)
	uevChan := make(chan *unEqVoteTest)
	count := 100
	errProb := float32(0.9)
	errsV := make(map[int]error)
	errsEv := make(map[int]error)
	errChan := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	ledger := generateTestVotes(uvChan, uevChan, errChan, ctx, count, errProb)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		c := 0
		for res := range outChan {
			c++
			var expectedError error
			if res.req.uv != nil {
				expectedError = errsV[int(res.index)]
			} else {
				expectedError = errsEv[int(res.index)]
			}
			if (expectedError == nil && res.err != nil) || (expectedError != nil && res.err == nil) {
				errChan <- fmt.Errorf("expected %v got %v", expectedError, res.err)
			}
			if c == count {
				break
			}
		}
		close(errChan)
	}()
	go func() {
		defer wg.Done()
		for c := 0; c < count; c++ {
			select {
			case uv := <-uvChan:
				errsV[uv.id] = uv.err
				voteVerifier.verifyVote(context.Background(), ledger, *uv.uv, uint64(uv.id), message{}, outChan)
			case uev := <-uevChan:
				errsEv[uev.id] = uev.err
				voteVerifier.verifyEqVote(context.Background(), ledger, *uev.uev, uint64(uev.id), message{}, outChan)
			case <-ctx.Done():
				return
			}
		}
		cancel()
		// flush any remaiing in the queue
		for range uvChan {
		}
		for range uevChan {
		}

	}()

	for err := range errChan {
		require.NoError(t, err)
		cancel()
	}
}

type unVoteTest struct {
	uv  *unauthenticatedVote
	err error
	id  int
}

type unEqVoteTest struct {
	uev *unauthenticatedEquivocationVote
	err error
	id  int
}

func generateTestVotes(uvChan chan<- *unVoteTest, uEqvChan chan<- *unEqVoteTest, errChan chan<- error, ctx context.Context, count int, errProb float32) (ledger Ledger) {
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)

	go func() {
		c := 0
		for {
			var processedVote = false
			var proposal proposalValue
			proposal.BlockDigest = randomBlockHash()

			for i, address := range addresses {
				proposal.OriginalProposer = address
				rv := rawVote{Sender: address, Round: round, Period: period, Step: step(0), Proposal: proposal}
				uv, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
				if err != nil {
					errChan <- err
				}
				//loop to find votes selected to participate
				//				fmt.Printf("A %s %d %d %d %+v\n", address, round, period, step(0), uv)
				m, err := membership(ledger, address, round, period, step(0))
				if err != nil {
					errChan <- err
				}
				_, err = uv.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)
				selected := err == nil
				if !selected {
					continue
				}
				processedVote = true

				errType := rand.Intn(7)
				if rand.Float32() > errProb {
					errType = 8
				}
				var v *unVoteTest
				switch errType {
				case 0:
					noSig := uv
					noSig.Sig = crypto.OneTimeSignature{}
					v = &unVoteTest{uv: &noSig, err: fmt.Errorf("no sig error"), id: c}

				case 1:
					noCred := uv
					noCred.Cred = committee.UnauthenticatedCredential{}
					v = &unVoteTest{uv: &noCred, err: fmt.Errorf("no cred error"), id: c}

				case 2:
					badRound := uv
					badRound.R.Round++
					v = &unVoteTest{uv: &badRound, err: fmt.Errorf("bad round error"), id: c}

				case 3:
					badPeriod := uv
					badPeriod.R.Period++
					v = &unVoteTest{uv: &badPeriod, err: fmt.Errorf("bad period error"), id: c}

				case 4:
					badStep := uv
					badStep.R.Step++
					v = &unVoteTest{uv: &badStep, err: fmt.Errorf("bad step error"), id: c}

				case 5:
					badBlockHash := uv
					badBlockHash.R.Proposal.BlockDigest = randomBlockHash()
					v = &unVoteTest{uv: &badBlockHash, err: fmt.Errorf("bad block hash error"), id: c}

				case 6:
					badProposer := uv
					badProposer.R.Proposal.OriginalProposer = basics.Address(randomBlockHash())
					v = &unVoteTest{uv: &badProposer, err: fmt.Errorf("bad proposer error"), id: c}

				default:
					v = &unVoteTest{uv: &uv, err: nil, id: c}
				}
				uvChan <- v
				break
			}
			c++
			if !processedVote {
				errChan <- fmt.Errorf("No votes were processed")
			}
			select {
			case <-ctx.Done():
				close(uvChan)
				return
			default:
			}

		}
	}()

	go func() {
		for {
			c := 0
			var proposal1 proposalValue
			proposal1.BlockDigest = randomBlockHash()

			var proposal2 proposalValue
			proposal2.BlockDigest = randomBlockHash()

			var processedVote = false
			for i, address := range addresses {
				proposal1.OriginalProposer = address
				rv0 := rawVote{Sender: address, Round: round, Period: period, Step: step(i), Proposal: proposal1}
				unauthenticatedVote0, err := makeVote(rv0, otSecrets[i], vrfSecrets[i], ledger)
				if err != nil {
					errChan <- err
				}

				rv0Copy := rawVote{Sender: address, Round: round, Period: period, Step: step(i), Proposal: proposal1}
				unauthenticatedVote0Copy, err := makeVote(rv0Copy, otSecrets[i], vrfSecrets[i], ledger)
				if err != nil {
					errChan <- err
				}

				rv1 := rawVote{Sender: address, Round: round, Period: period, Step: step(i), Proposal: proposal2}
				unauthenticatedVote1, err := makeVote(rv1, otSecrets[i], vrfSecrets[i], ledger)
				if err != nil {
					errChan <- err
				}

				ev := unauthenticatedEquivocationVote{
					Sender:    address,
					Round:     round,
					Period:    period,
					Step:      step(i),
					Cred:      unauthenticatedVote0.Cred,
					Proposals: [2]proposalValue{unauthenticatedVote0.R.Proposal, unauthenticatedVote1.R.Proposal},
					Sigs:      [2]crypto.OneTimeSignature{unauthenticatedVote0.Sig, unauthenticatedVote1.Sig},
				}

				evSameVote := unauthenticatedEquivocationVote{
					Sender:    address,
					Round:     round,
					Period:    period,
					Step:      step(i),
					Cred:      unauthenticatedVote0.Cred,
					Proposals: [2]proposalValue{unauthenticatedVote0.R.Proposal, unauthenticatedVote0Copy.R.Proposal},
					Sigs:      [2]crypto.OneTimeSignature{unauthenticatedVote0.Sig, unauthenticatedVote0Copy.Sig},
				}

				//loop to find votes selected to participate
				selected := ev.Sender == ev.Proposals[0].OriginalProposer
				if !selected {
					continue
				}
				processedVote = true

				errType := rand.Intn(9)
				if rand.Float32() > errProb {
					errType = 9
				}

				var v *unEqVoteTest
				switch errType {
				case 0:
					// check for same vote
					v = &unEqVoteTest{uev: &evSameVote, err: fmt.Errorf("error same vote"), id: c}

				case 1:
					noSig := ev
					noSig.Sigs = [2]crypto.OneTimeSignature{{}, {}}
					v = &unEqVoteTest{uev: &noSig, err: fmt.Errorf("error no sig"), id: c}

				case 2:
					noCred := ev
					noCred.Cred = committee.UnauthenticatedCredential{}
					v = &unEqVoteTest{uev: &noCred, err: fmt.Errorf("error no cred"), id: c}

				case 3:
					badRound := ev
					badRound.Round++
					v = &unEqVoteTest{uev: &badRound, err: fmt.Errorf("error bad round"), id: c}

				case 4:
					badPeriod := ev
					badPeriod.Period++
					v = &unEqVoteTest{uev: &badPeriod, err: fmt.Errorf("error bad period"), id: c}

				case 5:
					badStep := ev
					badStep.Step++
					v = &unEqVoteTest{uev: &badStep, err: fmt.Errorf("error bad step"), id: c}

				case 6:
					badBlockHash1 := ev
					badBlockHash1.Proposals[0].BlockDigest = randomBlockHash()
					v = &unEqVoteTest{uev: &badBlockHash1, err: fmt.Errorf("error bad block hash"), id: c}

				case 7:
					badBlockHash2 := ev
					badBlockHash2.Proposals[1].BlockDigest = randomBlockHash()
					v = &unEqVoteTest{uev: &badBlockHash2, err: fmt.Errorf("error bad block hash"), id: c}

				case 8:
					badSender := ev
					badSender.Sender = basics.Address{}
					v = &unEqVoteTest{uev: &badSender, err: fmt.Errorf("error bad sender"), id: c}

				default:
					v = &unEqVoteTest{uev: &ev, err: nil, id: c}

				}
				uEqvChan <- v
				break
			}
			c++
			if !processedVote {
				errChan <- fmt.Errorf("No votes were processed")
			}
			select {
			case <-ctx.Done():
				close(uEqvChan)
				return
			default:
			}
		}
	}()
	return ledger
}
