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
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

// BlockResponseContentType is the HTTP Content-Type header for a raw binary block
const BlockResponseContentType = "application/x-algorand-block-v1"
const blockResponseHasBlockCacheControl = "public, max-age=31536000, immutable"    // 31536000 seconds are one year.
const blockResponseMissingBlockCacheControl = "public, max-age=1, must-revalidate" // cache for 1 second, and force revalidation afterward
const blockServerMaxBodyLength = 512                                               // we don't really pass meaningful content here, so 512 bytes should be a safe limit
const blockServerCatchupRequestBufferSize = 10

// BlockServiceBlockPath is the path to register BlockService as a handler for when using gorilla/mux
// e.g. .Handle(BlockServiceBlockPath, &ls)
const BlockServiceBlockPath = "/v{version:[0-9.]+}/{genesisID}/block/{round:[0-9a-z]+}"

// BlockService represents the Block RPC API
type BlockService struct {
	ledger                  *data.Ledger
	genesisID               string
	catchupReqs             chan network.IncomingMessage
	stop                    chan struct{}
	net                     network.GossipNode
	enableService           bool
	enableServiceOverGossip bool
}

// EncodedBlockCert defines how GetBlockBytes encodes a block and its certificate
type EncodedBlockCert struct {
	_struct struct{} `codec:""`

	Block       bookkeeping.Block     `codec:"block"`
	Certificate agreement.Certificate `codec:"cert"`
}

// PreEncodedBlockCert defines how GetBlockBytes encodes a block and its certificate,
// using a pre-encoded Block and Certificate in msgpack format.
//msgp:ignore PreEncodedBlockCert
type PreEncodedBlockCert struct {
	Block       codec.Raw `codec:"block"`
	Certificate codec.Raw `codec:"cert"`
}

// MakeBlockService creates a BlockService around the provider Ledger and registers it for HTTP callback on the block serving path
func MakeBlockService(config config.Local, ledger *data.Ledger, net network.GossipNode, genesisID string) *BlockService {
	service := &BlockService{
		ledger:                  ledger,
		genesisID:               genesisID,
		catchupReqs:             make(chan network.IncomingMessage, config.CatchupParallelBlocks*blockServerCatchupRequestBufferSize),
		net:                     net,
		enableService:           config.EnableBlockService,
		enableServiceOverGossip: config.EnableGossipBlockService,
	}
	if service.enableService {
		net.RegisterHTTPHandler(BlockServiceBlockPath, service)
	}
	return service
}

// Start listening to catchup requests over ws
func (bs *BlockService) Start() {
	if bs.enableServiceOverGossip {
		handlers := []network.TaggedMessageHandler{
			{Tag: protocol.UniCatchupReqTag, MessageHandler: network.HandlerFunc(bs.processIncomingMessage)},
			{Tag: protocol.UniEnsBlockReqTag, MessageHandler: network.HandlerFunc(bs.processIncomingMessage)},
		}

		bs.net.RegisterHandlers(handlers)
	}
	bs.stop = make(chan struct{})
	go bs.ListenForCatchupReq(bs.catchupReqs, bs.stop)
}

// Stop servicing catchup requests over ws
func (bs *BlockService) Stop() {
	close(bs.stop)
}

// ServerHTTP returns blocks
// Either /v{version}/block/{round} or ?b={round}&v={version}
// Uses gorilla/mux for path argument parsing.
func (bs *BlockService) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	versionStr, hasVersionStr := pathVars["version"]
	roundStr, hasRoundStr := pathVars["round"]
	genesisID, hasGenesisID := pathVars["genesisID"]
	if hasVersionStr {
		if versionStr != "1" {
			logging.Base().Debug("http block bad version", versionStr)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if hasGenesisID {
		if bs.genesisID != genesisID {
			logging.Base().Debugf("http block bad genesisID mine=%#v theirs=%#v", bs.genesisID, genesisID)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		logging.Base().Debug("http block no genesisID")
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if (!hasVersionStr) || (!hasRoundStr) {
		// try query arg ?b={round}
		request.Body = http.MaxBytesReader(response, request.Body, blockServerMaxBodyLength)
		err := request.ParseForm()
		if err != nil {
			logging.Base().Debug("http block parse form err", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		roundStrs, ok := request.Form["b"]
		if !ok || len(roundStrs) != 1 {
			logging.Base().Debug("http block bad block id form arg")
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		roundStr = roundStrs[0]
		versionStrs, ok := request.Form["v"]
		if ok {
			if len(versionStrs) == 1 {
				if versionStrs[0] != "1" {
					logging.Base().Debug("http block bad version", versionStr)
					response.WriteHeader(http.StatusBadRequest)
					return
				}
			} else {
				logging.Base().Debug("http block wrong number of v args", len(versionStrs))
				response.WriteHeader(http.StatusBadRequest)
				return
			}
		} else {
			versionStr = "1"
		}
	}
	round, err := strconv.ParseUint(roundStr, 36, 64)
	if err != nil {
		logging.Base().Debug("http block round parse fail", roundStr, err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	encodedBlockCert, err := RawBlockBytes(bs.ledger, basics.Round(round))
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
			// entry cound not be found.
			response.Header().Set("Cache-Control", blockResponseMissingBlockCacheControl)
			response.WriteHeader(http.StatusNotFound)
			return
		default:
			// unexpected error.
			logging.Base().Warnf("ServeHTTP : failed to retrieve block %d %v", round, err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	response.Header().Set("Content-Type", BlockResponseContentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(encodedBlockCert)))
	response.Header().Set("Cache-Control", blockResponseHasBlockCacheControl)
	response.WriteHeader(http.StatusOK)
	_, err = response.Write(encodedBlockCert)
	if err != nil {
		logging.Base().Warn("http block write failed ", err)
	}
}

// WsGetBlockOut is a msgpack message delivered on responding to a block (not rpc-based though)
type WsGetBlockOut struct {
	Round      uint64
	Error      string
	BlockBytes []byte `json:"blockbytes"`
}

func (bs *BlockService) processIncomingMessage(msg network.IncomingMessage) (n network.OutgoingMessage) {
	// don't block - just stick in a slightly buffered channel if possible
	select {
	case bs.catchupReqs <- msg:
	default:
	}
	// don't return outgoing message, we just unicast instead
	return
}

// ListenForCatchupReq handles catchup getblock request
func (bs *BlockService) ListenForCatchupReq(reqs <-chan network.IncomingMessage, stop chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		select {
		case reqMsg := <-reqs:
			bs.handleCatchupReq(ctx, reqMsg)
		case <-stop:
			return
		}
	}
}

const noRoundNumberErrMsg = "can't find the round number"
const noDataTypeErrMsg = "can't find the data-type"
const roundNumberParseErrMsg = "unable to parse round number"
const blockNotAvailabeErrMsg = "requested block is not available"
const datatypeUnsupportedErrMsg = "requested data type is unsupported"

// a blocking function for handling a catchup request
func (bs *BlockService) handleCatchupReq(ctx context.Context, reqMsg network.IncomingMessage) {
	target := reqMsg.Sender.(network.UnicastPeer)
	var respTopics network.Topics

	defer func() {
		target.Respond(ctx, reqMsg, respTopics)
	}()

	topics, err := network.UnmarshallTopics(reqMsg.Data)
	if err != nil {
		logging.Base().Infof("BlockService handleCatchupReq: %s", err.Error())
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey, []byte(err.Error()))}
		return
	}
	roundBytes, found := topics.GetValue(network.RoundKey)
	if !found {
		logging.Base().Infof("BlockService handleCatchupReq: %s", noRoundNumberErrMsg)
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey,
				[]byte(noRoundNumberErrMsg))}
		return
	}
	requestType, found := topics.GetValue(network.RequestDataTypeKey)
	if !found {
		logging.Base().Infof("BlockService handleCatchupReq: %s", noDataTypeErrMsg)
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey,
				[]byte(noDataTypeErrMsg))}
		return
	}

	round, read := binary.Uvarint(roundBytes)
	if read <= 0 {
		logging.Base().Infof("BlockService handleCatchupReq: %s", roundNumberParseErrMsg)
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey,
				[]byte(roundNumberParseErrMsg))}
		return
	}
	respTopics = topicBlockBytes(bs.ledger, basics.Round(round), string(requestType))
	return
}

func topicBlockBytes(dataLedger *data.Ledger, round basics.Round, requestType string) network.Topics {
	blk, cert, err := dataLedger.EncodedBlockCert(round)
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
		default:
			logging.Base().Infof("BlockService topicBlockBytes: %s", err)
		}
		return network.Topics{
			network.MakeTopic(network.ErrorKey, []byte(blockNotAvailabeErrMsg))}
	}
	switch requestType {
	case network.BlockAndCertValue:
		return network.Topics{
			network.MakeTopic(
				network.BlockDataKey, blk),
			network.MakeTopic(
				network.CertDataKey, cert),
		}
	default:
		return network.Topics{
			network.MakeTopic(network.ErrorKey, []byte(datatypeUnsupportedErrMsg))}
	}
}

// RawBlockBytes return the msgpack bytes for a block
func RawBlockBytes(l *data.Ledger, round basics.Round) ([]byte, error) {
	blk, cert, err := l.EncodedBlockCert(round)
	if err != nil {
		return nil, err
	}

	if len(cert) == 0 {
		return nil, ledgercore.ErrNoEntry{Round: round}
	}

	return protocol.EncodeReflect(PreEncodedBlockCert{
		Block:       blk,
		Certificate: cert,
	}), nil
}
