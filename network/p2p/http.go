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

package p2p

import (
	"net/http"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2phttp "github.com/libp2p/go-libp2p/p2p/http"
)

// MakeHTTPClient creates a http.Client that uses libp2p transport for a goven protocol and peer address.
func MakeHTTPClient(protocolID string, addrInfo peer.AddrInfo) (http.Client, error) {
	clientStreamHost, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		return http.Client{}, err
	}

	client := libp2phttp.Host{StreamHost: clientStreamHost}

	// Do not use client.NamespacedClient to prevent it making connection to a well-known handler
	// to make a NamespaceRoundTripper that limits to specific URL paths.
	// First, we do not want make requests when listing peers (the main MakeHTTPClient invoker).
	// Secondly, this makes unit testing easier - no need to register fake handlers.
	rt, err := client.NewConstrainedRoundTripper(addrInfo)
	if err != nil {
		return http.Client{}, err
	}

	return http.Client{Transport: rt}, nil
}
