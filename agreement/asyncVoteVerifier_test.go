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
	"testing"

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

// Test async vote verifier against a canceled execution pool.
func TestVerificationAgainstFullExecutionPool(t *testing.T) {
	partitiontest.PartitionTest(t)
	mainPool := execpool.MakePool(t)
	defer mainPool.Shutdown()

	voteVerifier := MakeStartAsyncVoteVerifier(&expiredExecPool{mainPool})

	outChan := make(chan asyncVerifyVoteResponse, 1)
	voteVerifier.verifyVote(context.Background(), nil, unauthenticatedVote{}, 0, message{}, outChan)
	response := <-outChan
	require.Equal(t, execpool.ErrShuttingDownError, response.err)
	require.True(t, response.cancelled)
	voteVerifier.Quit()

	// Once the exec pool cancelation is detected, sending more jobs to the verifier will block
	// start again to test for eqVotes
	voteVerifier = MakeStartAsyncVoteVerifier(&expiredExecPool{mainPool})
	defer voteVerifier.Quit()
	voteVerifier.verifyEqVote(context.Background(), nil, unauthenticatedEquivocationVote{}, 0, message{}, outChan)
	response = <-outChan
	require.Equal(t, execpool.ErrShuttingDownError, response.err)
	require.True(t, response.cancelled)
}
