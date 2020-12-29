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
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util"
)

var errNoLedgerForRound = errors.New("No ledger available for given round")

const (
	// maxCatchpointFileChunkSize is a rough estimate for the worst-case scenario we're going to have of all the accounts data per a single catchpoint file chunk.
	maxCatchpointFileChunkSize = ledger.BalancesPerCatchpointFileChunk * basics.MaxEncodedAccountDataSize
	// defaultMinCatchpointFileDownloadBytesPerSecond defines the worst-case scenario download speed we expect to get while downloading a catchpoint file
	defaultMinCatchpointFileDownloadBytesPerSecond = 20 * 1024
	// catchpointFileStreamReadSize defines the number of bytes we would attempt to read at each itration from the incoming http data stream
	catchpointFileStreamReadSize = 4096
)

var errNoPeersAvailable = fmt.Errorf("downloadLedger : no peers are available")
var errNonHTTPPeer = fmt.Errorf("downloadLedger : non-HTTPPeer encountered")

type ledgerFetcherReporter interface {
	updateLedgerFetcherProgress(*ledger.CatchpointCatchupAccessorProgress)
}

type ledgerFetcher struct {
	net      network.GossipNode
	accessor ledger.CatchpointCatchupAccessor
	log      logging.Logger
	peers    []network.Peer
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

func (lf *ledgerFetcher) downloadLedger(ctx context.Context, round basics.Round) error {
	if len(lf.peers) == 0 {
		lf.peers = lf.net.GetPeers(network.PeersPhonebook)
		if len(lf.peers) == 0 {
			return errNoPeersAvailable
		}
	}
	peer, ok := lf.peers[0].(network.HTTPPeer)
	lf.peers = lf.peers[1:]
	if !ok {
		return errNonHTTPPeer
	}
	return lf.getPeerLedger(ctx, peer, round)
}

func (lf *ledgerFetcher) getPeerLedger(ctx context.Context, peer network.HTTPPeer, round basics.Round) error {
	parsedURL, err := network.ParseHostOrURL(peer.GetAddress())
	if err != nil {
		return err
	}

	parsedURL.Path = lf.net.SubstituteGenesisID(path.Join(parsedURL.Path, "/v1/{genesisID}/ledger/"+strconv.FormatUint(uint64(round), 36)))
	ledgerURL := parsedURL.String()
	lf.log.Debugf("ledger GET %#v peer %#v %T", ledgerURL, peer, peer)
	request, err := http.NewRequest(http.MethodGet, ledgerURL, nil)
	if err != nil {
		return err
	}

	timeoutContext, timeoutContextCancel := context.WithTimeout(ctx, lf.config.MaxCatchpointDownloadDuration)
	defer timeoutContextCancel()
	request = request.WithContext(timeoutContext)
	network.SetUserAgentHeader(request.Header)
	response, err := peer.GetHTTPClient().Do(request)
	if err != nil {
		lf.log.Debugf("getPeerLedger GET %v : %s", ledgerURL, err)
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

	// at this point, we've already receieved the response headers. ensure that the
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
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if header.Size > maxCatchpointFileChunkSize || header.Size < 1 {
			return fmt.Errorf("getPeerLedger received a tar header with data size of %d", header.Size)
		}
		balancesBlockBytes := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
			readComplete += int64(bytesRead)
			if err != nil {
				if err == io.EOF {
					if readComplete == header.Size {
						break
					}
					err = fmt.Errorf("getPeerLedger received io.EOF while reading from tar file stream prior of reaching chunk size %d / %d", readComplete, header.Size)
				}
				return err
			}
		}
		err = lf.processBalancesBlock(ctx, header.Name, balancesBlockBytes, &downloadProgress)
		if err != nil {
			return err
		}
		if lf.reporter != nil {
			lf.reporter.updateLedgerFetcherProgress(&downloadProgress)
		}
		if err = watchdogReader.Reset(); err != nil {
			if err == io.EOF {
				return nil
			}
			err = fmt.Errorf("getPeerLedger received the following error while reading the catchpoint file : %v", err)
			return err
		}
	}
}

func (lf *ledgerFetcher) processBalancesBlock(ctx context.Context, sectionName string, bytes []byte, downloadProgress *ledger.CatchpointCatchupAccessorProgress) error {
	return lf.accessor.ProgressStagingBalances(ctx, sectionName, bytes, downloadProgress)
}
