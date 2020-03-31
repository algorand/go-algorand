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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/rpcs"
)

var errNoLedgerForRound = errors.New("No ledger available for given round")

type ledgerFetcher struct {
	net      network.GossipNode
	accessor *ledger.CatchpointCatchupAccessor
	log      logging.Logger
	peers    []network.Peer
}

func makeLedgerFetcher(net network.GossipNode, accessor *ledger.CatchpointCatchupAccessor, log logging.Logger) *ledgerFetcher {
	return &ledgerFetcher{
		net:      net,
		accessor: accessor,
		log:      log,
	}
}

func (lf *ledgerFetcher) getLedger(ctx context.Context, round basics.Round) error {
	fmt.Printf("getLedger called for round %d\n", round)
	if len(lf.peers) == 0 {
		lf.peers = lf.net.GetPeers(network.PeersPhonebook)
		if len(lf.peers) == 0 {
			return fmt.Errorf("no peers are available")
		}
	}
	// use the first one -
	for {
		peer, ok := lf.peers[0].(network.HTTPPeer)
		lf.peers = lf.peers[1:]
		if !ok {
			return fmt.Errorf("non-HTTPPeer encountered")
		}
		return lf.getPeerLedger(ctx, peer, round)

	}
}

func (lf *ledgerFetcher) getPeerLedger(ctx context.Context, peer network.HTTPPeer, round basics.Round) error {
	defer fmt.Printf("getPeerLedger -exit \n")
	parsedURL, err := network.ParseHostOrURL(peer.GetAddress())
	if err != nil {
		return err
	}
	parsedURL.Path = peer.PrepareURL(path.Join(parsedURL.Path, "/v1/{genesisID}/ledger/"+strconv.FormatUint(uint64(round), 36)))
	ledgerURL := parsedURL.String()
	lf.log.Debugf("ledger GET %#v peer %#v %T", ledgerURL, peer, peer)
	fmt.Printf("ledger GET %#v \n", ledgerURL)
	request, err := http.NewRequest("GET", ledgerURL, nil)
	if err != nil {
		return err
	}
	request = request.WithContext(ctx)
	network.SetUserAgentHeader(request.Header)
	response, err := peer.GetHTTPClient().Do(request)
	if err != nil {
		lf.log.Debugf("GET %#v : %s", ledgerURL, err)
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
	fmt.Printf("getPeerLedger - before reading\n")

	// at this point, we've already receieved the response headers. ensure that the
	// response content type is what we'd like it to be.
	contentTypes := response.Header["Content-Type"]
	if len(contentTypes) != 1 {
		err = fmt.Errorf("http ledger fetcher invalid content type count %d", len(contentTypes))
		return err
	}

	if contentTypes[0] != rpcs.LedgerResponseContentType {
		err = fmt.Errorf("http ledger fetcher response has an invalid content type : %s", contentTypes[0])
		return err
	}

	tarReader := tar.NewReader(response.Body)
	for {
		fmt.Printf("getPeerLedger -tarReader.Next\n")
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				fmt.Printf("tarReader - no more headers\n")
				return nil
			}
			return err
		}
		balancesBlockBytes := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			fmt.Printf("getPeerLedger - read loop %d / %d\n", readComplete, header.Size)
			bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
			if err != nil {
				if err == io.EOF {
					readComplete += int64(bytesRead)
					if readComplete == header.Size {
						break
					}
					err = fmt.Errorf("unable to complete reading chunk data")
				}
				return err
			}
			readComplete += int64(bytesRead)
		}
		fmt.Printf("getPeerLedger - processBalancesBlock\n")
		err = lf.processBalancesBlock(ctx, header.Name, balancesBlockBytes)
		if err != nil {
			return err
		}
	}
}

func (lf *ledgerFetcher) processBalancesBlock(ctx context.Context, sectionName string, bytes []byte) error {
	return lf.accessor.ProgressStagingBalances(ctx, sectionName, bytes)
}
