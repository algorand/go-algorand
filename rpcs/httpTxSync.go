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

package rpcs

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/bloom"
)

// HTTPTxSync implements the TxSyncClient interface over HTTP
type HTTPTxSync struct {
	rootURL string

	peers network.GossipNode

	log logging.Logger

	maxTxSyncResponseBytes uint64
}

const requestContentType = "application/x-www-form-urlencoded"

// ResponseBytes reads the content of the response object and return the body content
// while obeying the read size limits
func ResponseBytes(response *http.Response, log logging.Logger, limit uint64) (data []byte, err error) {
	// response.Body is always non-nil
	defer response.Body.Close()
	if response.ContentLength >= 0 {
		if uint64(response.ContentLength) > limit {
			log.Errorf("response too large: %d > %d", response.ContentLength, limit)
			return nil, network.ErrIncomingMsgTooLarge
		}
		data = make([]byte, response.ContentLength)
		_, err = io.ReadFull(response.Body, data)
		return
	}
	slurper := network.LimitedReaderSlurper{Limit: limit}
	err = slurper.Read(response.Body)
	if err == network.ErrIncomingMsgTooLarge {
		log.Errorf("response too large: %d > %d", slurper.Size(), limit)
	}
	if err != nil {
		return nil, err
	}
	return slurper.Bytes(), err
}

// create a new http sync object.
func makeHTTPSync(peerSource network.GossipNode, log logging.Logger, serverResponseSize uint64) *HTTPTxSync {
	const transactionArrayEncodingOverhead = uint64(16) // manual tests shown that the actual extra packing cost is typically 3 bytes. We'll take 16 byte to ensure we're on the safe side.
	return &HTTPTxSync{
		peers:                  peerSource,
		log:                    log,
		maxTxSyncResponseBytes: serverResponseSize + transactionArrayEncodingOverhead,
	}
}

// Sync gets pending transactions from a random peer.
// Part of TxSyncClient interface.
func (hts *HTTPTxSync) Sync(ctx context.Context, bloom *bloom.Filter) (txgroups [][]transactions.SignedTxn, err error) {
	bloomBytes, err := bloom.MarshalBinary()
	if err != nil {
		hts.log.Errorf("txSync could not encode bloom filter: %s", err)
		return nil, err
	}
	bloomParam := base64.URLEncoding.EncodeToString(bloomBytes)

	peers := hts.peers.GetPeers(network.PeersPhonebook)
	if len(peers) == 0 {
		return nil, nil //errors.New("no peers to tx sync from")
	}
	peer := peers[rand.Intn(len(peers))]
	hpeer, ok := peer.(network.HTTPPeer)
	if !ok {
		return nil, fmt.Errorf("cannot HTTPTxSync non http peer %T %#v", peer, peer)
	}
	hts.rootURL = hpeer.GetAddress()
	client := hpeer.GetHTTPClient()
	if client == nil {
		client = &http.Client{}
		client.Transport = hts.peers.GetRoundTripper()
	}
	parsedURL, err := network.ParseHostOrURL(hts.rootURL)
	if err != nil {
		hts.log.Warnf("txSync bad url %v: %s", hts.rootURL, err)
		return nil, err
	}
	parsedURL.Path = hpeer.PrepareURL(path.Join(parsedURL.Path, TxServiceHTTPPath))
	syncURL := parsedURL.String()
	hts.log.Infof("http sync from %s", syncURL)
	params := url.Values{}
	params.Set("bf", bloomParam)
	request, err := http.NewRequest("POST", syncURL, strings.NewReader(params.Encode()))
	if err != nil {
		hts.log.Errorf("txSync POST setup %v: %s", syncURL, err)
		return nil, err
	}
	request.Header.Set("Content-Type", requestContentType)
	network.SetUserAgentHeader(request.Header)
	request = request.WithContext(ctx)
	response, err := client.Do(request)
	if err != nil {
		hts.log.Warnf("txSync POST %v: %s", syncURL, err)
		return nil, err
	}
	// check to see that we had no errors.
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNoContent: // server has no transactions for us.
		response.Body.Close()
		return [][]transactions.SignedTxn{}, nil
	default:
		hts.log.Warn("txSync response status code : ", response.StatusCode)
		response.Body.Close()
		return nil, fmt.Errorf("txSync POST error response status code %d for '%s'. Request bloom filter length was %d bytes", response.StatusCode, syncURL, len(bloomParam))
	}

	// at this point, we've already receieved the response headers. ensure that the
	// response content type is what we'd like it to be.
	contentTypes := response.Header["Content-Type"]
	if len(contentTypes) != 1 {
		err = fmt.Errorf("txSync POST invalid content type count %d", len(contentTypes))
		hts.log.Warn(err)
		response.Body.Close()
		return nil, err
	}
	// TODO: Temporarily allow old and new content types so we have time for lazy upgrades
	// Remove this 'old' string after next release.
	const responseContentTypeOld = "application/x-algorand-ptx-v1"
	if contentTypes[0] != responseContentType && contentTypes[0] != responseContentTypeOld {
		hts.log.Warnf("http response has an invalid content type : %s", contentTypes[0])
		response.Body.Close()
		return nil, fmt.Errorf("txSync POST invalid content type '%s'", contentTypes[0])
	}

	data, err := ResponseBytes(response, hts.log, hts.maxTxSyncResponseBytes)
	if err != nil {
		hts.log.Warn("txSync body read failed: ", err)
		return nil, err
	}
	hts.log.Debugf("http sync got %d bytes", len(data))

	var txns []transactions.SignedTxn
	err = protocol.DecodeReflect(data, &txns)
	if err != nil {
		hts.log.Warn("txSync protocol decode: ", err)
	}

	return bookkeeping.SignedTxnsToGroups(txns), err
}

// Address is part of TxSyncClient interface.
// Returns the root URL of the connected peer.
func (hts *HTTPTxSync) Address() string {
	return hts.rootURL
}

// Close is part of TxSyncClient interface
//
// Does nothing, leaves underlying client open because other HTTP
// requests from other interfaces could be open on it. Somewhere a
// Peer owns that connection and will close as needed.
func (hts *HTTPTxSync) Close() error {
	return nil
}
