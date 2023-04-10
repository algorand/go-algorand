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

// TestProcessBatchOneCtxCancled tests the case where one of the jobs in a batch has a cancled ctx
func TestProcessBatchOneCtxCancled(t *testing.T) {

	batchSize := 8
	cancelCtxIndex := 3
	outChan := make(chan interface{})
	bp := voteBatchProcessor{outChan: outChan}

	// case of a batch with a ctx cancled request/job
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture10()
	round := ledger.NextRound()
	period := period(0)

	votes := getVotes(batchSize, addresses, vrfSecrets, otSecrets, round, ledger, period, t)
	require.NotNil(t, votes)
	jobs := make([]execpool.InputJob, 0, batchSize)

	ctx := context.Background()
	ctxC, cancel := context.WithCancel(context.Background())
	cancel()
	out := make(chan asyncVerifyVoteResponse)

	// Create the batch job that the stream will accumulate jobs and create
	for v := range votes {
		req := asyncVerifyVoteRequest{
			ctx:     ctx,
			l:       ledger,
			uv:      &votes[v],
			index:   uint64(v),
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
	for range votes {
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

	batchSize := 30
	outChan := make(chan interface{})
	bp := voteBatchProcessor{outChan: outChan}

	// case of a batch with a ctx cancled request/job
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture10()
	round := ledger.NextRound()
	period := period(0)

	votes := getVotes(batchSize/2, addresses, vrfSecrets, otSecrets, round, ledger, period, t)
	require.NotNil(t, votes)
	eqVotes := getEqVotes(batchSize/2, addresses, vrfSecrets, otSecrets, round, ledger, period, t)
	require.NotNil(t, votes)

	jobs := make([]execpool.InputJob, 0, batchSize)

	ctx := context.Background()
	out := make(chan asyncVerifyVoteResponse)

	voteResults := make(map[int]*unVoteTest)
	eqVoteResults := make(map[int]*unEqVoteTest)

	// Create the batch job that the stream will accumulate jobs and create
	for v := range votes {
		vt := getTestVoteError(votes[v], v, v)
		voteResults[vt.id] = vt
		req := asyncVerifyVoteRequest{
			ctx:     ctx,
			l:       ledger,
			uv:      vt.uv,
			index:   uint64(v),
			message: message{},
			out:     out}
		jobs = append(jobs, &req)
	}
	for v := range eqVotes {
		vt := getTestEqVoteError(eqVotes[v][0], eqVotes[v][1], v, v)
		eqVoteResults[vt.id] = vt
		req := asyncVerifyVoteRequest{
			ctx:     ctx,
			l:       ledger,
			uev:     vt.uev,
			index:   uint64(v),
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
			if voteResults[int(resp.index)].err != nil {
				require.Error(t, resp.err)
				errCount++
			} else {
				require.NoError(t, resp.err)
				passCount++
			}
		} else {
			if eqVoteResults[int(resp.index)].err != nil {
				require.Error(t, resp.err)
				eqErrCount++
			} else {
				require.NoError(t, resp.err)
				eqPassCount++
			}
		}
	}
	require.Equal(t, 7, errCount)
	require.Equal(t, 8, passCount)
	require.Equal(t, 9, eqErrCount)
	require.Equal(t, 6, eqPassCount)
}

type fastSelector struct {
	committee.Selector
}

func (fs fastSelector) CommitteeSize(proto config.ConsensusParams) uint64 {
	return 10000
}

func getVotes(count int, addresses []basics.Address, vrfSecrets []*crypto.VRFSecrets, otSecrets []crypto.OneTimeSigner,
	round basics.Round, ledger Ledger, period period, t *testing.T) (votes []unauthenticatedVote) {
	var proposal proposalValue
	proposal.BlockDigest = randomBlockHash()
	votes = make([]unauthenticatedVote, 0, count)

	var uv unauthenticatedVote
	var err error

	for v := 0; v < count; v++ {
		addrFine := false
		for i, address := range addresses {
			proposal.OriginalProposer = address
			rv := rawVote{Sender: address, Round: round, Period: period, Step: step(0), Proposal: proposal}
			uv, err = makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			m, err := membership(ledger, address, round, period, step(0))
			m.Selector = fastSelector{m.Selector}
			require.NoError(t, err)
			_, err = uv.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)
			if err != nil { // address not selected
				continue
			} else {
				addrFine = true
			}
		}
		if !addrFine {
			return nil
		}
		votes = append(votes, uv)
	}
	return votes
}

func getEqVotes(count int, addresses []basics.Address, vrfSecrets []*crypto.VRFSecrets, otSecrets []crypto.OneTimeSigner,
	round basics.Round, ledger Ledger, period period, t *testing.T) (votes [][2]unauthenticatedEquivocationVote) {
	var proposal1 proposalValue
	proposal1.BlockDigest = randomBlockHash()
	var proposal2 proposalValue
	proposal2.BlockDigest = randomBlockHash()
	var ev unauthenticatedEquivocationVote
	var evSameVote unauthenticatedEquivocationVote
	votes = make([][2]unauthenticatedEquivocationVote, 0, count)

	for v := 0; v < count; v++ {
		addrFine := false
		for i, address := range addresses {
			proposal1.OriginalProposer = address
			rv0 := rawVote{Sender: address, Round: round, Period: period, Step: step(0), Proposal: proposal1}
			unauthenticatedVote0, err := makeVote(rv0, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			rv0Copy := rawVote{Sender: address, Round: round, Period: period, Step: step(0), Proposal: proposal1}
			unauthenticatedVote0Copy, err := makeVote(rv0Copy, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			proposal2.OriginalProposer = address
			rv1 := rawVote{Sender: address, Round: round, Period: period, Step: step(0), Proposal: proposal2}
			unauthenticatedVote1, err := makeVote(rv1, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)

			ev = unauthenticatedEquivocationVote{
				Sender:    address,
				Round:     round,
				Period:    period,
				Step:      step(0),
				Cred:      unauthenticatedVote0.Cred,
				Proposals: [2]proposalValue{unauthenticatedVote0.R.Proposal, unauthenticatedVote1.R.Proposal},
				Sigs:      [2]crypto.OneTimeSignature{unauthenticatedVote0.Sig, unauthenticatedVote1.Sig},
			}
			evSameVote = unauthenticatedEquivocationVote{
				Sender:    address,
				Round:     round,
				Period:    period,
				Step:      step(0),
				Cred:      unauthenticatedVote0.Cred,
				Proposals: [2]proposalValue{unauthenticatedVote0.R.Proposal, unauthenticatedVote0Copy.R.Proposal},
				Sigs:      [2]crypto.OneTimeSignature{unauthenticatedVote0.Sig, unauthenticatedVote0Copy.Sig},
			}

			m, err := membership(ledger, address, round, period, step(0))
			m.Selector = fastSelector{m.Selector}
			require.NoError(t, err)
			_, err = ev.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)
			if err != nil { // address not selected
				continue
			} else {
				addrFine = true
			}
		}
		if !addrFine {
			return nil
		}
		votes = append(votes, [2]unauthenticatedEquivocationVote{ev, evSameVote})
	}
	return votes
}

func getTestVoteError(uv unauthenticatedVote, c, errType int) *unVoteTest {
	var v *unVoteTest
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

	default:
		v = &unVoteTest{uv: &uv, err: nil, id: c}
	}
	return v
}

func getTestEqVoteError(ev, evSameVote unauthenticatedEquivocationVote, c, errType int) *unEqVoteTest {
	var v *unEqVoteTest
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

	case 8:
		badSender := ev
		badSender.Sender = basics.Address{}
		v = &unEqVoteTest{uev: &badSender, err: fmt.Errorf("error bad sender"), id: c}

	default:
		v = &unEqVoteTest{uev: &ev, err: nil, id: c}

	}
	return v
}
