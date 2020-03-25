// Copyright (C) 2019-2020 Algorand, Inc.
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

package catchup

import (
	"context"
	"sync"

	"github.com/algorand/go-algorand/data"
	/*	"context"
		"fmt"
		"sync"
		"sync/atomic"
		"time"

		"github.com/algorand/go-algorand/agreement"
		"github.com/algorand/go-algorand/config"
		"github.com/algorand/go-algorand/crypto"
		"github.com/algorand/go-algorand/data/basics"
		"github.com/algorand/go-algorand/data/bookkeeping"
		"github.com/algorand/go-algorand/ledger"
		"github.com/algorand/go-algorand/logging"
		"github.com/algorand/go-algorand/logging/telemetryspec"
		"github.com/algorand/go-algorand/network"
		"github.com/algorand/go-algorand/protocol"
		"github.com/algorand/go-algorand/rpcs"*/)

// CatchpointCatchupNodeServices defines set of functionalities required by the node to be supplied for the catchpoint catchup service.
type CatchpointCatchupNodeServices interface {
	Ledger() *data.Ledger
}

// CatchpointCatchupService represents the catchpoint catchup service.
type CatchpointCatchupService struct {
	CatchpointLabel string
	node            CatchpointCatchupNodeServices
	ctx             context.Context
	cancelCtxFunc   context.CancelFunc
	running         sync.WaitGroup
}

// MakeCatchpointCatchupService creates a catchpoint catchup service
func MakeCatchpointCatchupService(catchpoint string, node CatchpointCatchupNodeServices) *CatchpointCatchupService {
	return &CatchpointCatchupService{
		CatchpointLabel: catchpoint,
		node:            node,
	}
}

// Start starts the catchpoint catchup service
func (cs *CatchpointCatchupService) Start(ctx context.Context) {
	cs.ctx, cs.cancelCtxFunc = context.WithCancel(ctx)
	cs.running.Add(1)
	go cs.run()

}

// Abort aborts the catchpoint catchup service
func (cs *CatchpointCatchupService) Abort() {

}

func (cs *CatchpointCatchupService) run() {
	defer cs.running.Done()
}
