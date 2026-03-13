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
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
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
	mainPool := execpool.MakePool(t)
	defer mainPool.Shutdown()

	voteVerifier := MakeAsyncVoteVerifier(&expiredExecPool{mainPool})
	defer voteVerifier.Quit()
	verifyErr := voteVerifier.verifyVote(context.Background(), nil, unauthenticatedVote{}, 0, message{}, make(chan<- asyncVerifyVoteResponse, 1))
	require.Equal(t, context.Canceled, verifyErr)
	verifyEqVoteErr := voteVerifier.verifyEqVote(context.Background(), nil, unauthenticatedEquivocationVote{}, 0, message{}, make(chan<- asyncVerifyVoteResponse, 1))
	require.Equal(t, context.Canceled, verifyEqVoteErr)
}

// TestAsyncVerificationVotes creates MakeAsyncVoteVerifier,
// sends Votes (50% valid) for verification, and checks the results
func TestAsyncVerificationVotes(t *testing.T) {
	partitiontest.PartitionTest(t)
	errProb := float32(0.5)
	numVotes := 200
	numEqVotes := 0
	sendReceiveVoteVerifications(false, errProb, numVotes, numEqVotes, t)
}

// TestAsyncVerificationEqVotes creates MakeAsyncVoteVerifier,
// sends EqVotes (50% valid) for verification, and checks the results
func TestAsyncVerificationEqVotes(t *testing.T) {
	partitiontest.PartitionTest(t)
	errProb := float32(0.5)
	numVotes := 0
	numEqVotes := 200
	sendReceiveVoteVerifications(false, errProb, numVotes, numEqVotes, t)
}

// TestAsyncVerification creates MakeAsyncVoteVerifier, sends
// Votes and EqVotes (50% valid) for verification, and checks the results
func TestAsyncVerification(t *testing.T) {
	partitiontest.PartitionTest(t)
	errProb := float32(0.5)
	numVotes := 200
	numEqVotes := 200
	sendReceiveVoteVerifications(false, errProb, numVotes, numEqVotes, t)
}

// BenchmarkAsyncVerification benchmarks the performance of verifying votes using MakeAsyncVoteVerifier
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

// BenchmarkAsyncVerificationVotes benchmarks the performance of verifying votes using MakeAsyncVoteVerifier
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

// BenchmarkAsyncVerificationEqVotes benchmarks the performance of verifying votes using MakeAsyncVoteVerifier
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
	voteVerifier := MakeAsyncVoteVerifier(nil)
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

type testVoteGenerator struct {
	addresses  []basics.Address
	vrfSecrets []*crypto.VRFSecrets
	otSecrets  []crypto.OneTimeSigner
	round      basics.Round
	ledger     Ledger
	period     period
	counter    uint64
	proposal   proposalValue
	proposal2  proposalValue
}

func makeTestVoteGenerator() testVoteGenerator {
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	proposal := proposalValue{BlockDigest: randomBlockHash()}
	proposal2 := proposalValue{BlockDigest: randomBlockHash()}
	tg := testVoteGenerator{
		addresses:  addresses,
		vrfSecrets: vrfSecrets,
		otSecrets:  otSecrets,
		round:      ledger.NextRound(),
		ledger:     ledger,
		period:     period(0),
		proposal:   proposal,
		proposal2:  proposal2,
	}
	return tg
}

const (
	notSelected = 8
	validVote   = 10
)

func (vg *testVoteGenerator) getTestVote(errType int) (v *unVoteTest, err error) {
	addrSelected := false
	proposal := vg.proposal
	var uv unauthenticatedVote
	c := int(vg.counter)
	vg.counter++
	for i, address := range vg.addresses {
		proposal.OriginalProposer = address
		rv := rawVote{Sender: address, Round: vg.round, Period: vg.period, Step: step(0), Proposal: proposal}
		uv, err = makeVote(rv, vg.otSecrets[i], vg.vrfSecrets[i], vg.ledger)
		if err != nil {
			return v, err
		}
		m, err := membership(vg.ledger, address, vg.round, vg.period, step(0))
		if err != nil {
			return v, err
		}
		_, err = uv.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)
		if err != nil { // address not selected
			if errType == notSelected {
				addrSelected = true
				break
			}
		} else {
			if errType != notSelected {
				addrSelected = true
				break
			}
		}
	}
	if !addrSelected {
		return v, fmt.Errorf("Could not select address")
	}

	switch errType {
	case 0:
		badSig := uv
		badSig.Sig.Sig[0] = badSig.Sig.Sig[0] + 1
		v = &unVoteTest{uv: &badSig, err: fmt.Errorf("bad sig error"), id: c}

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

	case 7:
		badRound := uv
		badRound.R.Round = badRound.R.Round + 1000
		v = &unVoteTest{uv: &badRound, err: fmt.Errorf("membership error"), id: c}

	case notSelected:
		v = &unVoteTest{uv: &uv, err: fmt.Errorf("address not selected"), id: c}

	case validVote:
		v = &unVoteTest{uv: &uv, err: nil, id: c}

	default:
		return v, fmt.Errorf("unrecognized option")
	}
	return v, nil
}

// invalidVoteOptions returns the number of invalide vote options produced
func (vg *testVoteGenerator) invalidVoteOptions() int {
	return 9
}

func (vg *testVoteGenerator) getTestEqVote(errType int) (v *unEqVoteTest, err error) {
	var ev unauthenticatedEquivocationVote
	var evSameVote unauthenticatedEquivocationVote

	addrSelected := false
	proposal1 := vg.proposal
	proposal2 := vg.proposal2

	c := int(vg.counter)
	vg.counter++
	for i, address := range vg.addresses {
		proposal1.OriginalProposer = address
		rv0 := rawVote{Sender: address, Round: vg.round, Period: vg.period, Step: step(0), Proposal: proposal1}
		unauthenticatedVote0, err := makeVote(rv0, vg.otSecrets[i], vg.vrfSecrets[i], vg.ledger)
		if err != nil {
			return v, err
		}
		rv0Copy := rawVote{Sender: address, Round: vg.round, Period: vg.period, Step: step(0), Proposal: proposal1}
		proposal2.OriginalProposer = address
		rv1 := rawVote{Sender: address, Round: vg.round, Period: vg.period, Step: step(0), Proposal: proposal2}
		unauthenticatedVote1, err := makeVote(rv1, vg.otSecrets[i], vg.vrfSecrets[i], vg.ledger)
		if err != nil {
			return v, err
		}

		ev = unauthenticatedEquivocationVote{
			Sender:    address,
			Round:     vg.round,
			Period:    vg.period,
			Step:      step(0),
			Cred:      unauthenticatedVote0.Cred,
			Proposals: [2]proposalValue{unauthenticatedVote0.R.Proposal, unauthenticatedVote1.R.Proposal},
			Sigs:      [2]crypto.OneTimeSignature{unauthenticatedVote0.Sig, unauthenticatedVote1.Sig},
		}
		if errType == 0 {
			unauthenticatedVote0Copy, err := makeVote(rv0Copy, vg.otSecrets[i], vg.vrfSecrets[i], vg.ledger)
			if err != nil {
				return v, err
			}
			evSameVote = unauthenticatedEquivocationVote{
				Sender:    address,
				Round:     vg.round,
				Period:    vg.period,
				Step:      step(0),
				Cred:      unauthenticatedVote0.Cred,
				Proposals: [2]proposalValue{unauthenticatedVote0.R.Proposal, unauthenticatedVote0Copy.R.Proposal},
				Sigs:      [2]crypto.OneTimeSignature{unauthenticatedVote0.Sig, unauthenticatedVote0Copy.Sig},
			}
		}
		m, err := membership(vg.ledger, address, vg.round, vg.period, step(0))
		if err != nil {
			return v, err
		}

		_, err = ev.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)
		if err != nil { // address not selected
			if errType == notSelected {
				addrSelected = true
				break
			}
		} else {
			if errType != notSelected {
				addrSelected = true
				break
			}
		}
	}
	if !addrSelected {
		return v, fmt.Errorf("Could not select address")
	}

	switch errType {
	case 0:
		badSig := ev
		badSig.Sigs[0].Sig[0] = badSig.Sigs[0].Sig[0] + 1
		v = &unEqVoteTest{uev: &badSig, err: fmt.Errorf("error bad sig"), id: c}

	case 1:
		// check for same vote
		v = &unEqVoteTest{uev: &evSameVote, err: fmt.Errorf("error same vote"), id: c}

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

	case notSelected:
		v = &unEqVoteTest{uev: &ev, err: fmt.Errorf("error address not selected"), id: c}

	case 9:
		badSender := ev
		badSender.Sender = basics.Address{}
		v = &unEqVoteTest{uev: &badSender, err: fmt.Errorf("error bad sender"), id: c}

	case validVote:
		v = &unEqVoteTest{uev: &ev, err: nil, id: c}

	default:
		return v, fmt.Errorf("unrecognized option")
	}
	return v, nil
}

// invalidEqVoteOptions returns the number of invalide vote options produced
func (vg *testVoteGenerator) invalidEqVoteOptions() int {
	return 10
}
