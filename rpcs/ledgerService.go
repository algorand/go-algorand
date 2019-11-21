// Copyright (C) 2019 Algorand, Inc.
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
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

const ledgerResponseContentType = "application/x-algorand-block-v1"
const ledgerResponseHasBlockCacheControl = "public, max-age=31536000, immutable"    // 31536000 seconds are one year.
const ledgerResponseMissingBlockCacheControl = "public, max-age=1, must-revalidate" // cache for 1 second, and force revalidation afterward
const ledgerServerMaxBodyLength = 512                                               // we don't really pass meaningful content here, so 512 bytes should be a safe limit
const ledgerServerCatchupRequestBufferSize = 10

// LedgerService represents the Ledger RPC API
type LedgerService struct {
	ledger      *data.Ledger
	genesisID   string
	catchupReqs chan network.IncomingMessage
	stop        chan struct{}
}

// EncodedBlockCert defines how GetBlockBytes encodes a block and its certificate
type EncodedBlockCert struct {
	Block       bookkeeping.Block     `codec:"block"`
	Certificate agreement.Certificate `codec:"cert"`
}

// PreEncodedBlockCert defines how GetBlockBytes encodes a block and its certificate,
// using a pre-encoded Block and Certificate in msgpack format.
type PreEncodedBlockCert struct {
	Block       codec.Raw `codec:"block"`
	Certificate codec.Raw `codec:"cert"`
}

// RegisterLedgerService creates a LedgerService around the provider Ledger and registers it for RPC with the provided Registrar
func RegisterLedgerService(config config.Local, ledger *data.Ledger, registrar Registrar, genesisID string) *LedgerService {
	service := &LedgerService{ledger: ledger, genesisID: genesisID}
	registrar.RegisterHTTPHandler(LedgerServiceBlockPath, service)
	c := make(chan network.IncomingMessage, config.CatchupParallelBlocks*ledgerServerCatchupRequestBufferSize)

	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.UniCatchupReqTag, MessageHandler: network.HandlerFunc(service.processIncomingMessage)},
		{Tag: protocol.UniEnsBlockReqTag, MessageHandler: network.HandlerFunc(service.processIncomingMessage)},
	}

	registrar.RegisterHandlers(handlers)
	service.catchupReqs = c
	service.stop = make(chan struct{})

	return service
}

// Start listening to catchup requests over ws
func (ls *LedgerService) Start() {
	go ls.ListenForCatchupReq(ls.catchupReqs, ls.stop)
}

// Stop servicing catchup requests over ws
func (ls *LedgerService) Stop() {
	close(ls.stop)
}

// LedgerServiceBlockPath is the path to register LedgerService as a handler for when using gorilla/mux
// e.g. .Handle(LedgerServiceBlockPath, &ls)
const LedgerServiceBlockPath = "/v{version:[0-9.]+}/{genesisID}/block/{round:[0-9a-z]+}"

// ServerHTTP returns blocks
// Either /v{version}/block/{round} or ?b={round}&v={version}
// Uses gorilla/mux for path argument parsing.
func (ls *LedgerService) ServeHTTP(response http.ResponseWriter, request *http.Request) {
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
		if ls.genesisID != genesisID {
			logging.Base().Debugf("http block bad genesisID mine=%#v theirs=%#v", ls.genesisID, genesisID)
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
		request.Body = http.MaxBytesReader(response, request.Body, ledgerServerMaxBodyLength)
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
	encodedBlockCert, err := ls.encodedBlockCert(round)
	if err != nil {
		switch err.(type) {
		case ledger.ErrNoEntry:
			// entry cound not be found.
			response.Header().Set("Cache-Control", ledgerResponseMissingBlockCacheControl)
			response.WriteHeader(http.StatusNotFound)
			return
		default:
			// unexpected error.
			logging.Base().Warnf("ServeHTTP : failed to retrieve block %d %v", round, err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	response.Header().Set("Content-Type", ledgerResponseContentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(encodedBlockCert)))
	response.Header().Set("Cache-Control", ledgerResponseHasBlockCacheControl)
	response.WriteHeader(http.StatusOK)
	_, err = response.Write(encodedBlockCert)
	if err != nil {
		logging.Base().Warn("http block write failed ", err)
	}
}

// WsGetBlockRequest is a msgpack message requesting a block
type WsGetBlockRequest struct {
	Round uint64 `json:"round"`
}

// WsGetBlockOut is a msgpack message delivered on responding to a block (not rpc-based though)
type WsGetBlockOut struct {
	Round      uint64
	Error      string
	BlockBytes []byte `json:"blockbytes"`
}

func (ls *LedgerService) processIncomingMessage(msg network.IncomingMessage) (n network.OutgoingMessage) {
	// don't block - just stick in a slightly buffered channel if possible
	select {
	case ls.catchupReqs <- msg:
	default:
	}
	// don't return outgoing message, we just unicast instead
	return
}

// ListenForCatchupReq handles catchup getblock request
func (ls *LedgerService) ListenForCatchupReq(reqs <-chan network.IncomingMessage, stop chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		select {
		case reqMsg := <-reqs:
			ls.handleCatchupReq(ctx, reqMsg)
		case <-stop:
			return
		}
	}
}

// a blocking function for handling a catchup request
func (ls *LedgerService) handleCatchupReq(ctx context.Context, reqMsg network.IncomingMessage) {
	var res WsGetBlockOut
	defer func() {
		ls.sendCatchupRes(ctx, reqMsg.Sender.(network.UnicastPeer), reqMsg.Tag, res)
	}()

	var req WsGetBlockRequest
	err := protocol.Decode(reqMsg.Data, &req)
	if err != nil {
		res.Error = err.Error()
		return
	}
	res.Round = req.Round
	encodedBlob, err := ls.encodedBlockCert(req.Round)
	if err != nil {
		res.Error = err.Error()
		return
	}
	res.BlockBytes = encodedBlob
	return
}

func (ls *LedgerService) sendCatchupRes(ctx context.Context, target network.UnicastPeer, reqTag protocol.Tag, outMsg WsGetBlockOut) {
	t := reqTag.Complement()
	logging.Base().Infof("catching down peer: %v, round %v. outcome: %v. ledger: %v", target.GetAddress(), outMsg.Round, outMsg.Error, ls.ledger.LastRound())
	err := target.Unicast(ctx, protocol.Encode(outMsg), t)
	if err != nil {
		logging.Base().Info("failed to respond to catchup req", err)
	}
}

func (ls *LedgerService) encodedBlockCert(round uint64) ([]byte, error) {
	blk, cert, err := ls.ledger.EncodedBlockCert(basics.Round(round))
	if err != nil {
		return nil, err
	}

	return protocol.Encode(PreEncodedBlockCert{
		Block:       blk,
		Certificate: cert,
	}), nil
}
