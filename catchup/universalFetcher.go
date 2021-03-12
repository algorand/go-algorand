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
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// UniversalFetcher fetches blocks either from an http peer or ws peer.
type universalBlockFetcher struct {
	config config.Local
	net    network.GossipNode
	log    logging.Logger
}

// makeUniversalFetcher returns a fetcher for http and ws peers.
func makeUniversalBlockFetcher(log logging.Logger, net network.GossipNode, config config.Local) *universalBlockFetcher {
	return &universalBlockFetcher{
		config: config,
		net:    net,
		log:    log}
}

// fetchBlock returns a block from the peer. The peer can be either an http or ws peer.
func (uf *universalBlockFetcher) fetchBlock(ctx context.Context, round basics.Round, peer network.Peer) (blk *bookkeeping.Block,
	cert *agreement.Certificate, downloadDuration time.Duration, err error) {

	var fetchedBuf []byte
	var address string
	if wsPeer, validWSPeer := peer.(network.UnicastPeer); validWSPeer {
		fetcherClient := &wsFetcherClient{
			target: wsPeer,
			config: &uf.config,
		}
		fetchedBuf, err = fetcherClient.getBlockBytes(ctx, round)
		address = fetcherClient.address()
	} else if httpPeer, validHTTPPeer := peer.(network.HTTPPeer); validHTTPPeer {
		fetcherClient := &HTTPFetcher{
			peer:    httpPeer,
			rootURL: httpPeer.GetAddress(),
			net:     uf.net,
			client:  httpPeer.GetHTTPClient(),
			log:     uf.log,
			config:  &uf.config}
		fetchedBuf, err = fetcherClient.getBlockBytes(ctx, round)
		address = fetcherClient.address()
	} else {
		return nil, nil, time.Duration(0), fmt.Errorf("fetchBlock: UniversalFetcher only supports HTTPPeer and UnicastPeer")
	}
	if err != nil {
		return nil, nil, time.Duration(0), err
	}
	block, cert, err := processBlockBytes(fetchedBuf, round, address)
	if err != nil {
		return nil, nil, time.Duration(0), err
	}
	return block, cert, downloadDuration, err
}

func processBlockBytes(fetchedBuf []byte, r basics.Round, debugStr string) (blk *bookkeeping.Block, cert *agreement.Certificate, err error) {
	var decodedEntry rpcs.EncodedBlockCert
	err = protocol.Decode(fetchedBuf, &decodedEntry)
	if err != nil {
		err = fmt.Errorf("fetchBlock(%d): cannot decode block from peer %v: %v", r, debugStr, err)
		return
	}

	if decodedEntry.Block.Round() != r {
		err = fmt.Errorf("fetchBlock(%d): got wrong block from peer %v: wanted %v, got %v", r, debugStr, r, decodedEntry.Block.Round())
		return
	}

	if decodedEntry.Certificate.Round != r {
		err = fmt.Errorf("fetchBlock(%d): got wrong cert from peer %v: wanted %v, got %v", r, debugStr, r, decodedEntry.Certificate.Round)
		return
	}
	return &decodedEntry.Block, &decodedEntry.Certificate, nil
}

// a stub fetcherClient to satisfy the NetworkFetcher interface
type wsFetcherClient struct {
	target network.UnicastPeer // the peer where we're going to send the request.
	config *config.Local

	mu deadlock.Mutex
}

// getBlockBytes implements FetcherClient
func (w *wsFetcherClient) getBlockBytes(ctx context.Context, r basics.Round) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

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
func (w *wsFetcherClient) address() string {
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

// set max fetcher size to 5MB, this is enough to fit the block and certificate
const fetcherMaxBlockBytes = 5 << 20

var errNoBlockForRound = errors.New("No block available for given round")

// HTTPFetcher implements FetcherClient doing an HTTP GET of the block
type HTTPFetcher struct {
	peer    network.HTTPPeer
	rootURL string
	net     network.GossipNode

	client *http.Client

	log    logging.Logger
	config *config.Local
}

// getBlockBytes gets a block.
// Core piece of FetcherClient interface
func (hf *HTTPFetcher) getBlockBytes(ctx context.Context, r basics.Round) (data []byte, err error) {
	parsedURL, err := network.ParseHostOrURL(hf.rootURL)
	if err != nil {
		return nil, err
	}

	parsedURL.Path = hf.net.SubstituteGenesisID(path.Join(parsedURL.Path, "/v1/{genesisID}/block/"+strconv.FormatUint(uint64(r), 36)))
	blockURL := parsedURL.String()
	hf.log.Debugf("block GET %#v peer %#v %T", blockURL, hf.peer, hf.peer)
	request, err := http.NewRequest("GET", blockURL, nil)
	if err != nil {
		return nil, err
	}
	requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(hf.config.CatchupHTTPBlockFetchTimeoutSec)*time.Second)
	defer requestCancel()
	request = request.WithContext(requestCtx)
	network.SetUserAgentHeader(request.Header)
	response, err := hf.client.Do(request)
	if err != nil {
		hf.log.Debugf("GET %#v : %s", blockURL, err)
		return nil, err
	}

	// check to see that we had no errors.
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound: // server could not find a block with that round numbers.
		response.Body.Close()
		return nil, errNoBlockForRound
	default:
		bodyBytes, err := rpcs.ResponseBytes(response, hf.log, fetcherMaxBlockBytes)
		hf.log.Warnf("HTTPFetcher.getBlockBytes: response status code %d from '%s'. Response body '%s' ", response.StatusCode, blockURL, string(bodyBytes))
		if err == nil {
			err = fmt.Errorf("getBlockBytes error response status code %d when requesting '%s'. Response body '%s'", response.StatusCode, blockURL, string(bodyBytes))
		} else {
			err = fmt.Errorf("getBlockBytes error response status code %d when requesting '%s'. %w", response.StatusCode, blockURL, err)
		}
		return nil, err
	}

	// at this point, we've already receieved the response headers. ensure that the
	// response content type is what we'd like it to be.
	contentTypes := response.Header["Content-Type"]
	if len(contentTypes) != 1 {
		err = fmt.Errorf("http block fetcher invalid content type count %d", len(contentTypes))
		hf.log.Warn(err)
		response.Body.Close()
		return nil, err
	}

	// TODO: Temporarily allow old and new content types so we have time for lazy upgrades
	// Remove this 'old' string after next release.
	const blockResponseContentTypeOld = "application/algorand-block-v1"
	if contentTypes[0] != rpcs.BlockResponseContentType && contentTypes[0] != blockResponseContentTypeOld {
		hf.log.Warnf("http block fetcher response has an invalid content type : %s", contentTypes[0])
		response.Body.Close()
		return nil, fmt.Errorf("http block fetcher invalid content type '%s'", contentTypes[0])
	}

	return rpcs.ResponseBytes(response, hf.log, fetcherMaxBlockBytes)
}

// Address is part of FetcherClient interface.
// Returns the root URL of the connected peer.
func (hf *HTTPFetcher) address() string {
	return hf.rootURL
}

