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
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/rpcs"
)

// set max fetcher size to 5MB, this is enough to fit the block and certificate
const fetcherMaxBlockBytes = 5 << 20

var errNoBlockForRound = errors.New("No block available for given round")

// FetcherClient abstracts how to GetBlockBytes from a node on the net.
type FetcherClient interface {
	GetBlockBytes(ctx context.Context, r basics.Round) (data []byte, err error)
	Address() string
	Close() error
}

// HTTPFetcher implements FetcherClient doing an HTTP GET of the block
type HTTPFetcher struct {
	peer    network.HTTPPeer
	rootURL string
	net     network.GossipNode

	client *http.Client

	log    logging.Logger
	config *config.Local
}

// MakeHTTPFetcher wraps an HTTPPeer so that we can get blocks from it
func MakeHTTPFetcher(log logging.Logger, peer network.HTTPPeer, net network.GossipNode, cfg *config.Local) (fc FetcherClient) {
	fc = &HTTPFetcher{
		peer:    peer,
		rootURL: peer.GetAddress(),
		net:     net,
		client:  peer.GetHTTPClient(),
		log:     log,
		config:  cfg}
	return
}

// GetBlockBytes gets a block.
// Core piece of FetcherClient interface
func (hf *HTTPFetcher) GetBlockBytes(ctx context.Context, r basics.Round) (data []byte, err error) {
	parsedURL, err := network.ParseHostOrURL(hf.rootURL)
	if err != nil {
		return nil, err
	}
	parsedURL.Path = hf.peer.PrepareURL(path.Join(parsedURL.Path, "/v1/{genesisID}/block/"+strconv.FormatUint(uint64(r), 36)))
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
		hf.log.Warn("http block fetcher response status code : ", response.StatusCode)
		bodyBytes, err := rpcs.ResponseBytes(response, hf.log, fetcherMaxBlockBytes)
		if err == nil {
			err = fmt.Errorf("GetBlockBytes error response status code %d when requesting '%s'. Response body '%s'", response.StatusCode, blockURL, string(bodyBytes))
		} else {
			err = fmt.Errorf("GetBlockBytes error response status code %d when requesting '%s'. %w", response.StatusCode, blockURL, err)
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
func (hf *HTTPFetcher) Address() string {
	return hf.rootURL
}

// Close is part of FetcherClient interface
//
// Does nothing, leaves underlying client open because other HTTP
// requests from other interfaces could be open on it. Somewhere a
// Peer owns that connection and will close as needed.
func (hf *HTTPFetcher) Close() error {
	return nil
}
