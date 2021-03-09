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

package catchup

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// a stub fetcherClient to satisfy the NetworkFetcher interface
type wsFetcherClient struct {
	target      network.UnicastPeer                    // the peer where we're going to send the request.
	config      *config.Local

	closed bool // a flag indicating that the fetcher will not perform additional block retrivals.

	mu deadlock.Mutex
}

// getBlockBytes implements FetcherClient
func (w *wsFetcherClient) getBlockBytes(ctx context.Context, r basics.Round) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, fmt.Errorf("wsFetcherClient(%d): shutdown", r)
	}

	childCtx, cancelFunc := context.WithTimeout(ctx, time.Duration(w.config.CatchupGossipBlockFetchTimeoutSec)*time.Second)
	w.mu.Unlock()

	defer func() {
		cancelFunc()
		// note that we don't need to have additional Unlock here since
		// we already have a defered Unlock above ( which executes in reversed order )
		w.mu.Lock()
	}()

	blockBytes, err := w.requestBlock(childCtx, r)
	if err != nil {
		return nil, err
	}
	if len(blockBytes) == 0 {
		return nil, fmt.Errorf("wsFetcherClient(%d): empty response", r)
	}
	return blockBytes, nil
}

// Address implements FetcherClient
func (w *wsFetcherClient) Address() string {
	return fmt.Sprintf("[ws] (%v)", w.target.GetAddress())
}

// requestBlock send a request for block <round> and wait until it receives a response or a context expires.
func (w *wsFetcherClient) requestBlock(ctx context.Context, round basics.Round) ([]byte, error) {
	roundBin := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(roundBin, uint64(round))
	topics := network.Topics{
		network.MakeTopic(rpcs.RequestDataTypeKey,
			[]byte(rpcs.BlockAndCertValue)),
		network.MakeTopic(
			rpcs.RoundKey,
			roundBin),
	}
	resp, err := w.target.Request(ctx, protocol.UniEnsBlockReqTag, topics)
	if err != nil {
		return nil, fmt.Errorf("wsFetcherClient(%s).requestBlock(%d): Request failed, %v", w.target.GetAddress(), round, err)
	}

	if errMsg, found := resp.Topics.GetValue(network.ErrorKey); found {
		return nil, fmt.Errorf("wsFetcherClient(%s).requestBlock(%d): Request failed, %s", w.target.GetAddress(), round, string(errMsg))
	}

	blk, found := resp.Topics.GetValue(rpcs.BlockDataKey)
	if !found {
		return nil, fmt.Errorf("wsFetcherClient(%s): request failed: block data not found", w.target.GetAddress())
	}
	cert, found := resp.Topics.GetValue(rpcs.CertDataKey)
	if !found {
		return nil, fmt.Errorf("wsFetcherClient(%s): request failed: cert data not found", w.target.GetAddress())
	}

	blockCertBytes := protocol.EncodeReflect(rpcs.PreEncodedBlockCert{
		Block:       blk,
		Certificate: cert})

	return blockCertBytes, nil
}
