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

package rpcs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/mux"

	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/addr"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

// BlockResponseContentType is the HTTP Content-Type header for a raw binary block
const BlockResponseContentType = "application/x-algorand-block-v1"
const blockResponseHasBlockCacheControl = "public, max-age=31536000, immutable"    // 31536000 seconds are one year.
const blockResponseMissingBlockCacheControl = "public, max-age=1, must-revalidate" // cache for 1 second, and force revalidation afterward
const blockResponseRetryAfter = "3"                                                // retry after 3 seconds
const blockServerMaxBodyLength = 512                                               // we don't really pass meaningful content here, so 512 bytes should be a safe limit
const blockServerCatchupRequestBufferSize = 10

// BlockResponseLatestRoundHeader is returned in the response header when the requested block is not available
const BlockResponseLatestRoundHeader = "X-Latest-Round"

// BlockServiceBlockPath is the path to register BlockService as a handler for when using gorilla/mux
// e.g. .HandleFunc(BlockServiceBlockPath, ls.ServeBlockPath)
const BlockServiceBlockPath = "/v{version:[0-9.]+}/{genesisID}/block/{round:[0-9a-z]+}"

// Constant strings used as keys for topics
const (
	RoundKey           = "roundKey"        // Block round-number topic-key in the request
	RequestDataTypeKey = "requestDataType" // Data-type topic-key in the request (e.g. block, cert, block+cert)
	BlockDataKey       = "blockData"       // Block-data topic-key in the response
	CertDataKey        = "certData"        // Cert-data topic-key in the response
	BlockAndCertValue  = "blockAndCert"    // block+cert request data (as the value of requestDataTypeKey)
	LatestRoundKey     = "latest"
)

var errBlockServiceClosed = errors.New("block service is shutting down")

const errMemoryAtCapacityPublic = "block service memory over capacity"

type errMemoryAtCapacity struct{ capacity, used uint64 }

func (err errMemoryAtCapacity) Error() string {
	return fmt.Sprintf("block service memory over capacity: %d / %d", err.used, err.capacity)
}

var wsBlockMessagesDroppedCounter = metrics.MakeCounter(
	metrics.MetricName{Name: "algod_rpcs_ws_reqs_dropped", Description: "Number of websocket block requests dropped due to memory capacity"},
)
var httpBlockMessagesDroppedCounter = metrics.MakeCounter(
	metrics.MetricName{Name: "algod_rpcs_http_reqs_dropped", Description: "Number of http block requests dropped due to memory capacity"},
)

// LedgerForBlockService describes the Ledger methods used by BlockService.
type LedgerForBlockService interface {
	EncodedBlockCert(rnd basics.Round) (blk []byte, cert []byte, err error)
}

// BlockService represents the Block RPC API
type BlockService struct {
	ledger                  LedgerForBlockService
	genesisID               string
	catchupReqs             chan network.IncomingMessage
	stop                    chan struct{}
	net                     network.GossipNode
	enableService           bool
	enableServiceOverGossip bool
	fallbackEndpoints       fallbackEndpoints
	log                     logging.Logger
	closeWaitGroup          sync.WaitGroup
	mu                      deadlock.Mutex
	memoryUsed              uint64
	wsMemoryUsed            atomic.Uint64
	memoryCap               uint64
}

// EncodedBlockCert defines how GetBlockBytes encodes a block and its certificate
type EncodedBlockCert struct {
	_struct struct{} `codec:""`

	Block       bookkeeping.Block     `codec:"block"`
	Certificate agreement.Certificate `codec:"cert"`
}

// PreEncodedBlockCert defines how GetBlockBytes encodes a block and its certificate,
// using a pre-encoded Block and Certificate in msgpack format.
//
//msgp:ignore PreEncodedBlockCert
type PreEncodedBlockCert struct {
	Block       codec.Raw `codec:"block"`
	Certificate codec.Raw `codec:"cert"`
}

type fallbackEndpoints struct {
	endpoints []string
	lastUsed  int
}

// MakeBlockService creates a BlockService around the provider Ledger and registers it for HTTP callback on the block serving path
func MakeBlockService(log logging.Logger, config config.Local, ledger LedgerForBlockService, net network.GossipNode, genesisID string) *BlockService {
	service := &BlockService{
		ledger:                  ledger,
		genesisID:               genesisID,
		catchupReqs:             make(chan network.IncomingMessage, config.CatchupParallelBlocks*blockServerCatchupRequestBufferSize),
		net:                     net,
		enableService:           config.EnableBlockService,
		enableServiceOverGossip: config.EnableGossipBlockService,
		fallbackEndpoints:       makeFallbackEndpoints(log, config.BlockServiceCustomFallbackEndpoints),
		log:                     log,
		memoryCap:               config.BlockServiceMemCap,
	}
	if service.enableService {
		service.RegisterHandlers(net)
	}
	return service
}

// RegisterHandlers registers the request handlers for BlockService's paths with the registrar.
func (bs *BlockService) RegisterHandlers(registrar Registrar) {
	registrar.RegisterHTTPHandlerFunc(BlockServiceBlockPath, bs.ServeBlockPath)
}

// Start listening to catchup requests over ws
func (bs *BlockService) Start() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.enableServiceOverGossip {
		handlers := []network.TaggedMessageHandler{
			{Tag: protocol.UniEnsBlockReqTag, MessageHandler: network.HandlerFunc(bs.processIncomingMessage)},
		}

		bs.net.RegisterHandlers(handlers)
	}
	bs.stop = make(chan struct{})
	bs.closeWaitGroup.Add(1)
	go bs.listenForCatchupReq(bs.catchupReqs, bs.stop)
}

// Stop servicing catchup requests over ws
func (bs *BlockService) Stop() {
	bs.log.Debug("block service is stopping")
	defer bs.log.Debug("block service has stopped")

	bs.mu.Lock()
	close(bs.stop)
	bs.mu.Unlock()
	bs.closeWaitGroup.Wait()
}

// ServeBlockPath returns blocks
// Either /v{version}/{genesisID}/block/{round} or ?b={round}&v={version}
// Uses gorilla/mux for path argument parsing.
func (bs *BlockService) ServeBlockPath(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	versionStr, hasVersionStr := pathVars["version"]
	roundStr, hasRoundStr := pathVars["round"]
	genesisID, hasGenesisID := pathVars["genesisID"]
	if hasVersionStr {
		if versionStr != "1" {
			bs.log.Debug("http block bad version", versionStr)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if hasGenesisID {
		if bs.genesisID != genesisID {
			bs.log.Debugf("http block bad genesisID mine=%#v theirs=%#v", bs.genesisID, genesisID)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		bs.log.Debug("http block no genesisID")
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if (!hasVersionStr) || (!hasRoundStr) {
		// try query arg ?b={round}
		request.Body = http.MaxBytesReader(response, request.Body, blockServerMaxBodyLength)
		err := request.ParseForm()
		if err != nil {
			bs.log.Debug("http block parse form err", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		roundStrs, ok := request.Form["b"]
		if !ok || len(roundStrs) != 1 {
			bs.log.Debug("http block bad block id form arg")
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		roundStr = roundStrs[0]
		versionStrs, ok := request.Form["v"]
		if ok {
			if len(versionStrs) == 1 {
				if versionStrs[0] != "1" {
					bs.log.Debug("http block bad version", versionStr)
					response.WriteHeader(http.StatusBadRequest)
					return
				}
			} else {
				bs.log.Debug("http block wrong number of v args", len(versionStrs))
				response.WriteHeader(http.StatusBadRequest)
				return
			}
		}
	}
	round, err := strconv.ParseUint(roundStr, 36, 64)
	if err != nil {
		bs.log.Debug("http block round parse fail", roundStr, err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	encodedBlockCert, err := bs.rawBlockBytes(basics.Round(round))
	if err != nil {
		switch lerr := err.(type) {
		case ledgercore.ErrNoEntry:
			// entry cound not be found.
			ok := bs.redirectRequest(round, response, request)
			if !ok {
				response.Header().Set("Cache-Control", blockResponseMissingBlockCacheControl)
				response.Header().Set(BlockResponseLatestRoundHeader, fmt.Sprintf("%d", lerr.Latest))
				response.WriteHeader(http.StatusNotFound)
			}
			return
		case errMemoryAtCapacity:
			// memory used by HTTP block requests is over the cap
			ok := bs.redirectRequest(round, response, request)
			if !ok {
				response.Header().Set("Retry-After", blockResponseRetryAfter)
				response.WriteHeader(http.StatusServiceUnavailable)
				bs.log.Debugf("ServeBlockPath: returned retry-after: %v", err)
			}
			httpBlockMessagesDroppedCounter.Inc(nil)
			return
		default:
			// unexpected error.
			bs.log.Warnf("ServeBlockPath: failed to retrieve block %d %v", round, err)
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
		bs.log.Warn("http block write failed ", err)
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.memoryUsed = bs.memoryUsed - uint64(len(encodedBlockCert))
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

// listenForCatchupReq handles catchup getblock request
func (bs *BlockService) listenForCatchupReq(reqs <-chan network.IncomingMessage, stop chan struct{}) {
	defer bs.closeWaitGroup.Done()
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
const blockNotAvailableErrMsg = "requested block is not available"
const datatypeUnsupportedErrMsg = "requested data type is unsupported"

// a blocking function for handling a catchup request
func (bs *BlockService) handleCatchupReq(ctx context.Context, reqMsg network.IncomingMessage) {
	target := reqMsg.Sender.(network.UnicastPeer)
	var respTopics network.Topics
	var n uint64

	defer func() {
		outMsg := network.OutgoingMessage{Topics: respTopics}
		if n > 0 {
			outMsg.OnRelease = func() {
				bs.wsMemoryUsed.Add(^uint64(n - 1))
			}
			bs.wsMemoryUsed.Add(n)
		}
		err := target.Respond(ctx, reqMsg, outMsg)
		if err != nil {
			bs.log.Warnf("BlockService handleCatchupReq: failed to respond: %s", err)
		}
	}()

	// If we are over-capacity, we will not process the request
	// respond to sender with error message
	memUsed := bs.wsMemoryUsed.Load()
	if memUsed > bs.memoryCap {
		err := errMemoryAtCapacity{capacity: bs.memoryCap, used: memUsed}
		bs.log.Infof("BlockService handleCatchupReq: %s", err.Error())
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey, []byte(errMemoryAtCapacityPublic)),
		}
		wsBlockMessagesDroppedCounter.Inc(nil)
		return
	}

	topics, err := network.UnmarshallTopics(reqMsg.Data)
	if err != nil {
		bs.log.Infof("BlockService handleCatchupReq: %s", err.Error())
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey, []byte(err.Error()))}
		return
	}
	roundBytes, found := topics.GetValue(RoundKey)
	if !found {
		bs.log.Infof("BlockService handleCatchupReq: %s", noRoundNumberErrMsg)
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey,
				[]byte(noRoundNumberErrMsg))}
		return
	}
	requestType, found := topics.GetValue(RequestDataTypeKey)
	if !found {
		bs.log.Infof("BlockService handleCatchupReq: %s", noDataTypeErrMsg)
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey,
				[]byte(noDataTypeErrMsg))}
		return
	}

	round, read := binary.Uvarint(roundBytes)
	if read <= 0 {
		bs.log.Infof("BlockService handleCatchupReq: %s", roundNumberParseErrMsg)
		respTopics = network.Topics{
			network.MakeTopic(network.ErrorKey,
				[]byte(roundNumberParseErrMsg))}
		return
	}
	respTopics, n = topicBlockBytes(bs.log, bs.ledger, basics.Round(round), string(requestType))
}

// redirectRequest redirects the request to the next round robin fallback endpoint if available
func (bs *BlockService) redirectRequest(round uint64, response http.ResponseWriter, request *http.Request) (ok bool) {
	peerAddress := bs.getNextCustomFallbackEndpoint()

	if peerAddress == "" {
		return false
	}

	var redirectURL string
	if addr.IsMultiaddr(peerAddress) {
		redirectURL = strings.Replace(FormatBlockQuery(round, "", bs.net), "{genesisID}", bs.genesisID, 1)
	} else {
		parsedURL, err := addr.ParseHostOrURL(peerAddress)
		if err != nil {
			bs.log.Debugf("redirectRequest: %s", err.Error())
			return false
		}
		parsedURL.Path = strings.Replace(FormatBlockQuery(round, parsedURL.Path, bs.net), "{genesisID}", bs.genesisID, 1)
		redirectURL = parsedURL.String()
	}
	http.Redirect(response, request, redirectURL, http.StatusTemporaryRedirect)
	bs.log.Debugf("redirectRequest: redirected block request to %s", redirectURL)
	return true
}

// getNextCustomFallbackEndpoint returns the next custom fallback endpoint in RR ordering
func (bs *BlockService) getNextCustomFallbackEndpoint() (endpointAddress string) {
	if len(bs.fallbackEndpoints.endpoints) == 0 {
		return
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()
	endpointAddress = bs.fallbackEndpoints.endpoints[bs.fallbackEndpoints.lastUsed]
	bs.fallbackEndpoints.lastUsed = (bs.fallbackEndpoints.lastUsed + 1) % len(bs.fallbackEndpoints.endpoints)
	return
}

// rawBlockBytes returns the block/cert for a given round, while taking the lock
// to ensure the block service is currently active.
func (bs *BlockService) rawBlockBytes(round basics.Round) ([]byte, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	select {
	case _, ok := <-bs.stop:
		if !ok {
			// service is closed.
			return nil, errBlockServiceClosed
		}
	default:
	}
	if bs.memoryUsed > bs.memoryCap {
		return nil, errMemoryAtCapacity{used: bs.memoryUsed, capacity: bs.memoryCap}
	}
	data, err := RawBlockBytes(bs.ledger, round)
	if err == nil {
		bs.memoryUsed = bs.memoryUsed + uint64(len(data))
	}
	return data, err
}

func topicBlockBytes(log logging.Logger, dataLedger LedgerForBlockService, round basics.Round, requestType string) (network.Topics, uint64) {
	blk, cert, err := dataLedger.EncodedBlockCert(round)
	if err != nil {
		switch lerr := err.(type) {
		case ledgercore.ErrNoEntry:
			return network.Topics{
				network.MakeTopic(network.ErrorKey, []byte(blockNotAvailableErrMsg)),
				network.MakeTopic(LatestRoundKey, binary.BigEndian.AppendUint64([]byte{}, uint64(lerr.Latest))),
			}, 0
		default:
			log.Infof("BlockService topicBlockBytes: %s", err)
		}
		return network.Topics{
			network.MakeTopic(network.ErrorKey, []byte(blockNotAvailableErrMsg))}, 0
	}
	switch requestType {
	case BlockAndCertValue:
		return network.Topics{
			network.MakeTopic(
				BlockDataKey, blk),
			network.MakeTopic(
				CertDataKey, cert),
		}, uint64(len(blk) + len(cert))
	default:
		return network.Topics{
			network.MakeTopic(network.ErrorKey, []byte(datatypeUnsupportedErrMsg))}, 0
	}
}

// RawBlockBytes return the msgpack bytes for a block
func RawBlockBytes(l LedgerForBlockService, round basics.Round) ([]byte, error) {
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

// FormatBlockQuery formats a block request query for the given network and round number
func FormatBlockQuery(round uint64, parsedURL string, net network.GossipNode) string {
	return network.SubstituteGenesisID(net, path.Join(parsedURL, "/v1/{genesisID}/block/"+strconv.FormatUint(uint64(round), 36)))
}

func makeFallbackEndpoints(log logging.Logger, customFallbackEndpoints string) (fe fallbackEndpoints) {
	if customFallbackEndpoints == "" {
		return
	}
	endpoints := strings.SplitSeq(customFallbackEndpoints, ",")
	for ep := range endpoints {
		if addr.IsMultiaddr(ep) {
			fe.endpoints = append(fe.endpoints, ep)
		} else {
			parsed, err := addr.ParseHostOrURL(ep)
			if err != nil {
				log.Warnf("makeFallbackEndpoints: error parsing %s %s", ep, err.Error())
				continue
			}
			fe.endpoints = append(fe.endpoints, parsed.String())
		}
	}
	return
}
