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
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

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
	parsedURL, err := network.ParseHostOrURL(peer.GetAddress())
	if err != nil {
		return err
	}
	parsedURL.Path = peer.PrepareURL(path.Join(parsedURL.Path, "/v1/{genesisID}/ledger/"+strconv.FormatUint(uint64(round), 36)))
	ledgerURL := parsedURL.String()
	lf.log.Debugf("ledger GET %#v peer %#v %T", ledgerURL, peer, peer)
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
	// TODO - validate content-type
	tarReader := tar.NewReader(response.Body)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		balancesBlockBytes := make([]byte, 0, header.Size)
		readComplete := int64(0)
		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			readComplete += int64(bytesRead)
		}
		err = lf.processBalancesBlock(ctx, header.Name, balancesBlockBytes)
		if err != nil {
			return err
		}
	}
}

func (lf *ledgerFetcher) processBalancesBlock(ctx context.Context, sectionName string, bytes []byte) error {
	return lf.accessor.ProgressStagingBalances(ctx, sectionName, bytes)
}
