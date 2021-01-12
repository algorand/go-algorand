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

package main

import (
	"context"
	"fmt"

	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
)

//////////////////////////////////////
// Helpers to initialize mockClient //
//////////////////////////////////////

func makeNodeStatuses(blocks ...uint64) (ret []generatedV2.NodeStatusResponse) {
	ret = make([]generatedV2.NodeStatusResponse, 0, len(blocks))
	for _, block := range blocks {
		ret = append(ret, generatedV2.NodeStatusResponse{LastRound: block})
	}
	return ret
}

func makeBlocks(blocks ...uint64) (ret map[uint64]v1.Block) {
	ret = map[uint64]v1.Block{}
	for _, block := range blocks {
		ret[block] = v1.Block{Round: block}
	}
	return ret
}

// Mock client...

type mockClient struct {
	StatusCalls        int
	BlockCalls         map[uint64]int
	GetGoRoutinesCalls int
	HealthCheckCalls   int
	error              []error
	status             []generatedV2.NodeStatusResponse
	routine            []string
	block              map[uint64]v1.Block
}

func makeMockClient(error []error, status []generatedV2.NodeStatusResponse, block map[uint64]v1.Block, routine []string) mockClient {
	return mockClient{
		BlockCalls: make(map[uint64]int),
		error:      error,
		status:     status,
		block:      block,
		routine:    routine,
	}
}

func (c *mockClient) nextError() (e error) {
	e = nil
	if len(c.error) > 0 {
		e = c.error[0]
		// Repeat last error...
		if len(c.error) > 1 {
			c.error = c.error[1:]
		}
	}
	return
}

func (c *mockClient) Status() (s generatedV2.NodeStatusResponse, e error) {
	c.StatusCalls++
	s = c.status[0]
	// Repeat last status...
	if len(c.status) > 1 {
		c.status = c.status[1:]
	}
	e = c.nextError()
	return
}

func (c *mockClient) Block(block uint64) (b v1.Block, e error) {
	c.BlockCalls[block]++
	e = c.nextError()
	b, ok := c.block[block]
	if !ok {
		if e == nil {
			e = fmt.Errorf("test is missing block %d", block)
		}
	}
	return
}

func (c *mockClient) GetGoRoutines(ctx context.Context) (r string, e error) {
	c.GetGoRoutinesCalls++
	r = c.routine[0]
	// Repeat last routine...
	if len(c.routine) > 1 {
		c.routine = c.routine[1:]
	}
	e = c.nextError()
	return
}

func (c *mockClient) HealthCheck() (e error) {
	c.HealthCheckCalls++
	// Repeat last healthcheck...
	if len(c.routine) > 1 {
		c.routine = c.routine[1:]
	}
	e = c.nextError()
	return
}
