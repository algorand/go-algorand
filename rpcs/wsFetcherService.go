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

package rpcs

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

// WsFetcherService exists for the express purpose or providing a global
// handler for fetcher gossip message response types
type WsFetcherService struct {
	log             logging.Logger
	mu              deadlock.RWMutex
	pendingRequests map[string]chan WsGetBlockOut
	net             network.GossipNode
}

// Constant strings used as keys for topics
const (
	roundKey           = "roundKey"        // Block round-number topic-key in the request
	requestDataTypeKey = "requestDataType" // Data-type topic-key in the request (e.g. block, cert, block+cert)
	blockDataKey       = "blockData"       // Block-data topic-key in the response
	certDataKey        = "certData"        // Cert-data topic-key in the response
	blockAndCertValue  = "blockAndCert"    // block+cert request data (as the value of requestDataTypeKey)
)

func makePendingRequestKey(target network.UnicastPeer, round basics.Round, tag protocol.Tag) string {
	return fmt.Sprintf("<%s>:%d:%s", target.GetAddress(), round, tag)

}

func (fs *WsFetcherService) handleNetworkMsg(msg network.IncomingMessage) (out network.OutgoingMessage) {
	// route message to appropriate wsFetcher (if registered)
	uniPeer := msg.Sender.(network.UnicastPeer)
	switch msg.Tag {
	case protocol.UniCatchupResTag:
	case protocol.UniEnsBlockResTag:
	default:
		fs.log.Warnf("WsFetcherService: unable to process message coming from '%s'; no fetcher registered for tag (%v)", uniPeer.GetAddress(), msg.Tag)
		return
	}

	var resp WsGetBlockOut

	if len(msg.Data) == 0 {
		fs.log.Warnf("WsFetcherService(%s): request failed: catchup response no bytes sent", uniPeer.GetAddress())
		out.Action = network.Disconnect
		return
	}

	if decodeErr := protocol.DecodeReflect(msg.Data, &resp); decodeErr != nil {
		fs.log.Warnf("WsFetcherService(%s): request failed: unable to decode message : %v", uniPeer.GetAddress(), decodeErr)
		out.Action = network.Disconnect
		return
	}

	waitKey := makePendingRequestKey(uniPeer, basics.Round(resp.Round), msg.Tag.Complement())
	fs.mu.RLock()
	f, hasWaitCh := fs.pendingRequests[waitKey]
	fs.mu.RUnlock()
	if !hasWaitCh {
		if resp.Error != "" {
			fs.log.Infof("WsFetcherService: received a message response for a stale block request from '%s', round %d, length %d, error : '%s'", uniPeer.GetAddress(), resp.Round, len(resp.BlockBytes), resp.Error)
		} else {
			fs.log.Infof("WsFetcherService: received a message response for a stale block request from '%s', round %d, length %d", uniPeer.GetAddress(), resp.Round, len(resp.BlockBytes))
		}
		return
	}

	f <- resp
	return
}

// RequestBlock send a request for block <round> and wait until it receives a response or a context expires.
func (fs *WsFetcherService) RequestBlock(ctx context.Context, target network.UnicastPeer, round basics.Round, tag protocol.Tag) (WsGetBlockOut, error) {
	waitCh := make(chan WsGetBlockOut, 1)
	waitKey := makePendingRequestKey(target, round, tag)

	// register.
	fs.mu.Lock()
	if _, has := fs.pendingRequests[waitKey]; has {
		// we already have a pending request for the same round and tag from the same peer
		fs.mu.Unlock()
		return WsGetBlockOut{}, fmt.Errorf("WsFetcherService.RequestBlock(%d): only single concurrent request for a round from a single peer(%s) is supported", round, target.GetAddress())
	}
	fs.pendingRequests[waitKey] = waitCh
	fs.mu.Unlock()

	defer func() {
		// unregister
		fs.mu.Lock()
		delete(fs.pendingRequests, waitKey)
		fs.mu.Unlock()
	}()
	if target.Version() == "1" {
		req := WsGetBlockRequest{Round: uint64(round)}
		err := target.Unicast(ctx, protocol.EncodeReflect(req), tag)
		if err != nil {
			return WsGetBlockOut{}, fmt.Errorf("WsFetcherService.RequestBlock(%d): unicast failed, %v", round, err)
		}
		select {
		case resp := <-waitCh:
			return resp, nil
		case <-ctx.Done():
			switch ctx.Err() {
			case context.DeadlineExceeded:
				return WsGetBlockOut{}, fmt.Errorf("WsFetcherService.RequestBlock(%d): request to %s was timed out", round, target.GetAddress())
			case context.Canceled:
				return WsGetBlockOut{}, fmt.Errorf("WsFetcherService.RequestBlock(%d): request to %s was cancelled by context", round, target.GetAddress())
			default:
				return WsGetBlockOut{}, ctx.Err()
			}
		}
	}

	// Else, if version == 2.1
	roundBin := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(roundBin, uint64(round))
	topics := network.Topics{
		network.MakeTopic(requestDataTypeKey,
			[]byte(blockAndCertValue)),
		network.MakeTopic(
			roundKey,
			roundBin),
	}
	resp, err := target.Request(ctx, tag, topics)
	if err != nil {
		return WsGetBlockOut{}, fmt.Errorf("WsFetcherService(%s).RequestBlock(%d): Request failed, %v", target.GetAddress(), round, err)
	}

	if errMsg, found := resp.Topics.GetValue(network.ErrorKey); found {
		return WsGetBlockOut{}, fmt.Errorf("WsFetcherService(%s).RequestBlock(%d): Request failed, %s", target.GetAddress(), round, string(errMsg))
	}

	blk, found := resp.Topics.GetValue(blockDataKey)
	if !found {
		return WsGetBlockOut{}, fmt.Errorf("WsFetcherService(%s): request failed: block data not found", target.GetAddress())
	}
	cert, found := resp.Topics.GetValue(certDataKey)
	if !found {
		return WsGetBlockOut{}, fmt.Errorf("WsFetcherService(%s): request failed: cert data not found", target.GetAddress())
	}

	// For backward compatibility, the block and cert are repackaged here.
	// This can be dropeed once the v1 is dropped.
	blockCertBytes := protocol.EncodeReflect(PreEncodedBlockCert{
		Block:       blk,
		Certificate: cert})

	wsBlockOut := WsGetBlockOut{
		Round:      uint64(round),
		BlockBytes: blockCertBytes,
	}
	return wsBlockOut, nil
}

// MakeWsFetcherService creates and returns a WsFetcherService that services gossip fetcher responses
func MakeWsFetcherService(log logging.Logger, net network.GossipNode) *WsFetcherService {
	service := &WsFetcherService{
		log:             log,
		pendingRequests: make(map[string]chan WsGetBlockOut),
		net:             net,
	}
	return service
}

// Start starts the WsFetcherService
func (fs *WsFetcherService) Start() {
	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.UniCatchupResTag, MessageHandler: network.HandlerFunc(fs.handleNetworkMsg)},  // handles the response for a block catchup request
		{Tag: protocol.UniEnsBlockResTag, MessageHandler: network.HandlerFunc(fs.handleNetworkMsg)}, // handles the response for a block ensure digest request
	}
	fs.net.RegisterHandlers(handlers)
}

// Stop stops the WsFetcherService
func (fs *WsFetcherService) Stop() {

}
