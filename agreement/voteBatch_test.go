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
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/stretchr/testify/require"
)

func dummyTaskMemVote() (*crypto.SigVerificationTask, *committee.Membership, *unauthenticatedVote) {
	task := crypto.SigVerificationTask{Message: rawVote{}}
	m := committee.Membership{Selector: selector{}}
	uv := unauthenticatedVote{}
	return &task, &m, &uv
}

func dummyTaskMemEqVote() ([]*crypto.SigVerificationTask, *committee.Membership, *unauthenticatedEquivocationVote) {
	task := crypto.SigVerificationTask{Message: rawVote{}}
	tasks := []*crypto.SigVerificationTask{&task, &task}
	m := committee.Membership{Selector: selector{}}
	ueqv := unauthenticatedEquivocationVote{}
	return tasks, &m, &ueqv
}

// TestVerificationTasks tests the verificationTasksAndResults bookkeeping and that getJobResult returns the expected records
func TestVerificationTasks(t *testing.T) {
	partitiontest.PartitionTest(t)

	numTasks := 5
	ledger, _, _, _ := readOnlyFixture100()

	// case of all Votes
	vtr := makeVerificationTasksAndResults(numTasks)
	for x := 0; x < numTasks; x++ {
		vtr.addVoteJob(dummyTaskMemVote())
	}
	vtr.failed = make([]bool, 5)
	vtr.failed[0] = true
	vtr.failed[3] = true

	for x := 0; x < numTasks; x++ {
		req := asyncVerifyVoteRequest{l: ledger}
		_, _, err := vtr.getJobResult(&req, x)
		if x == 0 || x == 3 {
			require.ErrorContains(t, err, "verificationTasksAndResults.getJobResult: could not verify FS signature on vote")
			continue
		}
		require.ErrorContains(t, err, "UnauthenticatedCredential.Verify: could not verify VRF Proof")
	}

	// case of all EqVotes
	vtr = makeVerificationTasksAndResults(numTasks)
	for x := 0; x < numTasks; x++ {
		vtr.addEqVoteJob(dummyTaskMemEqVote())
	}
	vtr.failed = make([]bool, 10)
	vtr.failed[3] = true // 2nd vote of 1
	vtr.failed[4] = true // 1st and 2nd votes of 2
	vtr.failed[5] = true
	vtr.failed[8] = true // 1st vote of 4
	for x := 0; x < numTasks; x++ {
		req := asyncVerifyVoteRequest{l: ledger}
		_, _, err := vtr.getJobResult(&req, x)
		if x == 1 || x == 2 || x == 4 {
			require.ErrorContains(t, err, "could not verify FS signature on vote by")
			continue
		}
		require.ErrorContains(t, err, "UnauthenticatedCredential.Verify: could not verify VRF Proof")
	}

	// case of mixed Votes EqVotes
	vtr = makeVerificationTasksAndResults(numTasks)
	for x := 0; x < numTasks; x++ {
		if x == 2 || x == 5 || x == 6 {
			vtr.addEqVoteJob(dummyTaskMemEqVote())
			continue
		}
		vtr.addVoteJob(dummyTaskMemVote())
	}
	//f:t      t              t       t
	//  0 1 (2 3) 4  5 (6 7) (8 9) 10 11 12
	//  0 1   2   3  4   5     6   7  8  9
	vtr.failed = make([]bool, 13)
	vtr.failed[0] = true
	vtr.failed[3] = true
	vtr.failed[8] = true
	vtr.failed[11] = true
	for x := 0; x < numTasks; x++ {
		req := asyncVerifyVoteRequest{l: ledger}
		_, _, err := vtr.getJobResult(&req, x)
		if x == 2 || x == 5 || x == 6 {
			// it must be eq vote
			if x == 5 {
				require.ErrorContains(t, err, "UnauthenticatedCredential.Verify: could not verify VRF Proof")
				continue
			}
			require.ErrorContains(t, err, "could not verify FS signature on vote by")
			continue
		}
		if x == 0 || x == 8 {
			require.ErrorContains(t, err, "verificationTasksAndResults.getJobResult: could not verify FS signature on vote")
			continue
		}
		require.ErrorContains(t, err, "UnauthenticatedCredential.Verify: could not verify VRF Proof")
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

const notSelected = 8

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

	default:
		v = &unVoteTest{uv: &uv, err: nil, id: c}
	}
	return v, nil
}

func (vg *testVoteGenerator) voteOptions() int {
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
		// check for same vote
		v = &unEqVoteTest{uev: &evSameVote, err: fmt.Errorf("error same vote"), id: c}

	case 1:
		badSig := ev
		badSig.Sigs[0].Sig[0] = badSig.Sigs[0].Sig[0] + 1
		v = &unEqVoteTest{uev: &badSig, err: fmt.Errorf("error bad sig"), id: c}

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

	default:
		v = &unEqVoteTest{uev: &ev, err: nil, id: c}

	}
	return v, nil
}

func (vg *testVoteGenerator) voteEqOptions() int {
	return 10
}

// TestProcessBatchOneCtxCancled tests the case where one of the jobs in a batch has a cancled ctx
func TestProcessBatchOneCtxCancled(t *testing.T) {
	partitiontest.PartitionTest(t)

	batchSize := 8
	cancelCtxIndex := 3
	outChan := make(chan interface{})
	bp := voteBatchProcessor{outChan: outChan}

	vg := makeTestVoteGenerator()

	ctx := context.Background()
	ctxC, cancel := context.WithCancel(context.Background())
	cancel()
	out := make(chan asyncVerifyVoteResponse)
	jobs := make([]execpool.InputJob, 0, batchSize)
	// Create the batch job that the stream will accumulate jobs and create
	for v := 0; v < batchSize; v++ {
		tv, err := vg.getTestVote(99)
		require.NoError(t, err)
		req := asyncVerifyVoteRequest{
			ctx:     ctx,
			l:       vg.ledger,
			uv:      tv.uv,
			index:   uint64(tv.id),
			message: message{},
			out:     out}
		// let one of the jobs get a cancled ctx
		if v == cancelCtxIndex {
			req.ctx = ctxC
		}
		jobs = append(jobs, &req)
	}

	// pass the batch to ProcessBatch, and expect it to process all the jobs except the one
	// with the cancled ctx
	go bp.ProcessBatch(jobs)
	for range jobs {
		e := <-outChan
		resp := e.(*asyncVerifyVoteResponse)
		if resp.err != nil {
			require.Equal(t, cancelCtxIndex, int(resp.req.index))
			require.ErrorIs(t, resp.err, resp.req.ctx.Err())
			continue
		}
		require.NoError(t, resp.err)
	}
}

// TestProcessBatchDifferentErrors tests the case where one of the jobs in a batch has a cancled ctx
func TestProcessBatchDifferentErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	batchSize := 30
	outChan := make(chan interface{})
	bp := voteBatchProcessor{outChan: outChan}

	vg := makeTestVoteGenerator()

	jobs := make([]execpool.InputJob, 0, batchSize)

	ctx := context.Background()
	out := make(chan asyncVerifyVoteResponse)

	voteResults := make(map[int]error)
	eqVoteResults := make(map[int]error)

	// Create the batch job that the stream will accumulate jobs and create
	for v := 0; v < vg.voteOptions()*2; v++ {
		vt, err := vg.getTestVote(v)
		require.NoError(t, err)
		voteResults[vt.id] = vt.err
		req := asyncVerifyVoteRequest{
			ctx:     ctx,
			l:       vg.ledger,
			uv:      vt.uv,
			index:   uint64(vt.id),
			message: message{},
			out:     out}
		jobs = append(jobs, &req)
	}
	for v := 0; v < vg.voteEqOptions()*2; v++ {
		vt, err := vg.getTestEqVote(v)
		require.NoError(t, err)
		eqVoteResults[vt.id] = vt.err
		req := asyncVerifyVoteRequest{
			ctx:     ctx,
			l:       vg.ledger,
			uev:     vt.uev,
			index:   uint64(vt.id),
			message: message{},
			out:     out}
		jobs = append(jobs, &req)
	}
	// pass the batch to ProcessBatch, and expect it to process all the jobs except the one
	// with the cancled ctx
	go bp.ProcessBatch(jobs)
	errCount := 0
	passCount := 0
	eqErrCount := 0
	eqPassCount := 0
	for range jobs {
		e := <-outChan
		resp := e.(*asyncVerifyVoteResponse)
		if resp.req.uv != nil {
			if voteResults[int(resp.index)] != nil {
				require.Error(t, resp.err)
				errCount++
			} else {
				require.NoError(t, resp.err)
				passCount++
			}
		} else {
			if eqVoteResults[int(resp.index)] != nil {
				require.Error(t, resp.err)
				eqErrCount++
			} else {
				require.NoError(t, resp.err)
				eqPassCount++
			}
		}
	}
	require.Equal(t, vg.voteOptions(), errCount)
	require.Equal(t, vg.voteOptions(), passCount)
	require.Equal(t, vg.voteEqOptions(), eqErrCount)
	require.Equal(t, vg.voteEqOptions(), eqPassCount)
}
