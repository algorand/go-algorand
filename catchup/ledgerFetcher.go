// Copyright (C) 2019-2024 Algorand, Inc.
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
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util"
)

var errNoLedgerForRound = errors.New("no ledger available for given round")

const (
	// maxCatchpointFileChunkSize is a rough estimate for the worst-case scenario we're going to have of all the accounts data per a single catchpoint file chunk and one account with max resources.
	maxCatchpointFileChunkSize = ledger.BalancesPerCatchpointFileChunk*(ledger.MaxEncodedBaseAccountDataSize+encoded.MaxEncodedKVDataSize) + ledger.ResourcesPerCatchpointFileChunk*ledger.MaxEncodedBaseResourceDataSize
	// defaultMinCatchpointFileDownloadBytesPerSecond defines the worst-case scenario download speed we expect to get while downloading a catchpoint file
	defaultMinCatchpointFileDownloadBytesPerSecond = 20 * 1024
	// catchpointFileStreamReadSize defines the number of bytes we would attempt to read at each iteration from the incoming http data stream
	catchpointFileStreamReadSize = 4096
)

var errNonHTTPPeer = fmt.Errorf("downloadLedger : non-HTTPPeer encountered")

type ledgerFetcherReporter interface {
	updateLedgerFetcherProgress(*ledger.CatchpointCatchupAccessorProgress)
}

type ledgerFetcher struct {
	net      network.GossipNode
	accessor ledger.CatchpointCatchupAccessor
	log      logging.Logger

	reporter ledgerFetcherReporter
	config   config.Local
}

func makeLedgerFetcher(net network.GossipNode, accessor ledger.CatchpointCatchupAccessor, log logging.Logger, reporter ledgerFetcherReporter, cfg config.Local) *ledgerFetcher {
	return &ledgerFetcher{
		net:      net,
		accessor: accessor,
		log:      log,
		reporter: reporter,
		config:   cfg,
	}
}

func (lf *ledgerFetcher) requestLedger(ctx context.Context, peer network.HTTPPeer, round basics.Round, method string) (*http.Response, error) {
	ledgerURL := network.SubstituteGenesisID(lf.net, "/v1/{genesisID}/ledger/"+strconv.FormatUint(uint64(round), 36))
	lf.log.Debugf("ledger %s %#v peer %#v %T", method, ledgerURL, peer, peer)
	request, err := http.NewRequestWithContext(ctx, method, ledgerURL, nil)
	if err != nil {
		return nil, err
	}

	network.SetUserAgentHeader(request.Header)
	httpClient := peer.GetHTTPClient()
	if httpClient == nil {
		return nil, fmt.Errorf("requestLedger: HTTPPeer %s has no http client", peer.GetAddress())
	}
	return httpClient.Do(request)
}

func (lf *ledgerFetcher) headLedger(ctx context.Context, peer network.Peer, round basics.Round) error {
	httpPeer, ok := peer.(network.HTTPPeer)
	if !ok {
		return errNonHTTPPeer
	}
	timeoutContext, timeoutContextCancel := context.WithTimeout(ctx, lf.config.MaxCatchpointDownloadDuration)
	defer timeoutContextCancel()
	response, err := lf.requestLedger(timeoutContext, httpPeer, round, http.MethodHead)
	if err != nil {
		lf.log.Debugf("getPeerLedger HEAD : %s", err)
		return err
	}
	defer func() { _ = response.Body.Close() }()

	// check to see that we had no errors.
	switch response.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound: // server could not find a block with that round number.
		return errNoLedgerForRound
	default:
		return fmt.Errorf("headLedger error response status code %d", response.StatusCode)
	}
}

func (lf *ledgerFetcher) downloadLedger(ctx context.Context, peer network.Peer, round basics.Round) error {
	httpPeer, ok := peer.(network.HTTPPeer)
	if !ok {
		return errNonHTTPPeer
	}
	return lf.getPeerLedger(ctx, httpPeer, round)
}

func (lf *ledgerFetcher) getPeerLedger(ctx context.Context, peer network.HTTPPeer, round basics.Round) error {
	timeoutContext, timeoutContextCancel := context.WithTimeout(ctx, lf.config.MaxCatchpointDownloadDuration)
	defer timeoutContextCancel()
	response, err := lf.requestLedger(timeoutContext, peer, round, http.MethodGet)
	if err != nil {
		lf.log.Debugf("getPeerLedger GET : %s", err)
		return err
	}
	defer response.Body.Close()

	// check to see that we had no errors.
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound: // server could not find a block with that round numbers.
		return errNoLedgerForRound
	default:
		return fmt.Errorf("getPeerLedger error response status code %d", response.StatusCode)
	}

	// at this point, we've already received the response headers. ensure that the
	// response content type is what we'd like it to be.
	contentTypes := response.Header["Content-Type"]
	if len(contentTypes) != 1 {
		err = fmt.Errorf("getPeerLedger : http ledger fetcher invalid content type count %d", len(contentTypes))
		return err
	}

	if contentTypes[0] != rpcs.LedgerResponseContentType {
		err = fmt.Errorf("getPeerLedger : http ledger fetcher response has an invalid content type : %s", contentTypes[0])
		return err
	}

	// maxCatchpointFileChunkDownloadDuration is the maximum amount of time we would wait to download a single chunk off a catchpoint file
	maxCatchpointFileChunkDownloadDuration := 2 * time.Minute
	if lf.config.MinCatchpointFileDownloadBytesPerSecond > 0 {
		maxCatchpointFileChunkDownloadDuration += maxCatchpointFileChunkSize * time.Second / time.Duration(lf.config.MinCatchpointFileDownloadBytesPerSecond)
	} else {
		maxCatchpointFileChunkDownloadDuration += maxCatchpointFileChunkSize * time.Second / defaultMinCatchpointFileDownloadBytesPerSecond
	}

	watchdogReader := util.MakeWatchdogStreamReader(response.Body, catchpointFileStreamReadSize, 2*maxCatchpointFileChunkSize, maxCatchpointFileChunkDownloadDuration)
	defer watchdogReader.Close()
	tarReader := tar.NewReader(watchdogReader)
	var downloadProgress ledger.CatchpointCatchupAccessorProgress
	var writeDuration time.Duration

	printLogsFunc := func() {
		lf.log.Infof(
			"writing balances to disk took %d seconds, "+
				"writing creatables to disk took %d seconds, "+
				"writing hashes to disk took %d seconds, "+
				"writing kv pairs to disk took %d seconds, "+
				"total duration is %d seconds",
			downloadProgress.BalancesWriteDuration/time.Second,
			downloadProgress.CreatablesWriteDuration/time.Second,
			downloadProgress.HashesWriteDuration/time.Second,
			downloadProgress.KVWriteDuration/time.Second,
			writeDuration/time.Second)
	}

	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				printLogsFunc()
				return nil
			}
			return err
		}
		if header.Size > maxCatchpointFileChunkSize || header.Size < 1 {
			return fmt.Errorf("getPeerLedger received a tar header with data size of %d", header.Size)
		}
		balancesBlockBytes := make([]byte, header.Size)
		_, err = io.ReadFull(tarReader, balancesBlockBytes)
		if err != nil {
			return err
		}
		start := time.Now()
		err = lf.processBalancesBlock(ctx, header.Name, balancesBlockBytes, &downloadProgress)
		if err != nil {
			return err
		}
		writeDuration += time.Since(start)
		if lf.reporter != nil {
			lf.reporter.updateLedgerFetcherProgress(&downloadProgress)
		}
		if err = watchdogReader.Reset(); err != nil {
			if err == io.EOF {
				printLogsFunc()
				return nil
			}
			err = fmt.Errorf("getPeerLedger received the following error while reading the catchpoint file : %v", err)
			return err
		}
	}
}

func (lf *ledgerFetcher) processBalancesBlock(ctx context.Context, sectionName string, bytes []byte, downloadProgress *ledger.CatchpointCatchupAccessorProgress) error {
	return lf.accessor.ProcessStagingBalances(ctx, sectionName, bytes, downloadProgress)
}
