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

package txnsync

import (
	"context"
	"sync"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/execpool"
)

// Service is the transaction sync main service object.
type Service struct {
	ctx       context.Context
	cancelCtx context.CancelFunc
	waitGroup sync.WaitGroup

	state syncState
}

// MakeTranscationSyncService creates a new Service object
func MakeTranscationSyncService(log logging.Logger, conn NodeConnector, isRelay bool, genesisID string, genesisHash crypto.Digest, cfg config.Local, threadpool execpool.BacklogPool) *Service {
	s := &Service{
		state: syncState{
			node:        conn,
			log:         wrapLogger(log),
			isRelay:     isRelay,
			genesisID:   genesisID,
			genesisHash: genesisHash,
			config:      cfg,
			threadpool:  threadpool,
		},
	}
	s.state.service = s
	s.state.xorBuilder.MaxIterations = 10
	return s
}

// Start starts the transaction sync
func (s *Service) Start() {
	s.ctx, s.cancelCtx = context.WithCancel(context.Background())
	s.waitGroup.Add(1)

	go s.state.mainloop(s.ctx, &s.waitGroup)
}

// Stop stops the transaction sync
func (s *Service) Stop() {
	// cancel the context
	s.cancelCtx()
	// wait until the mainloop exists.
	s.waitGroup.Wait()
	// clear the context, as we won't be using it anymore.
	s.cancelCtx, s.ctx = nil, nil
}

// GetIncomingMessageHandler returns the message handler.
func (s *Service) GetIncomingMessageHandler() IncomingMessageHandler {
	return s.state.asyncIncomingMessageHandler
}
