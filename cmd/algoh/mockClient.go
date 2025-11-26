// Copyright (C) 2019-2025 Algorand, Inc.
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

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

//////////////////////////////////////
// Helpers to initialize mockClient //
//////////////////////////////////////

func makeNodeStatuses(blocks ...basics.Round) (ret []model.NodeStatusResponse) {
	ret = make([]model.NodeStatusResponse, 0, len(blocks))
	for _, block := range blocks {
		ret = append(ret, model.NodeStatusResponse{LastRound: block})
	}
	return ret
}

func makeBlocks(blocks ...basics.Round) (ret map[basics.Round]rpcs.EncodedBlockCert) {
	ret = map[basics.Round]rpcs.EncodedBlockCert{}
	for _, block := range blocks {
		ret[block] = rpcs.EncodedBlockCert{Block: bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: basics.Round(block)}}}
	}
	return ret
}

// Mock client...

type mockClient struct {
	StatusCalls        int
	BlockCalls         map[basics.Round]int
	GetGoRoutinesCalls int
	HealthCheckCalls   int
	error              []error
	status             []model.NodeStatusResponse
	routine            []string
	block              map[basics.Round]rpcs.EncodedBlockCert
}

func makeMockClient(error []error, status []model.NodeStatusResponse, block map[basics.Round]rpcs.EncodedBlockCert, routine []string) mockClient {
	return mockClient{
		BlockCalls: make(map[basics.Round]int),
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

func (c *mockClient) Status() (s model.NodeStatusResponse, e error) {
	c.StatusCalls++
	s = c.status[0]
	// Repeat last status...
	if len(c.status) > 1 {
		c.status = c.status[1:]
	}
	e = c.nextError()
	return
}

func (c *mockClient) RawBlock(block basics.Round) (b []byte, e error) {
	c.BlockCalls[block]++
	e = c.nextError()
	bl, ok := c.block[block]
	if !ok {
		if e == nil {
			e = fmt.Errorf("test is missing block %d", block)
		}
	}
	b = protocol.EncodeReflect(bl)
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
