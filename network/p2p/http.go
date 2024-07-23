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
	"sync"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/limitcaller"
	"github.com/gorilla/mux"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2phttp "github.com/libp2p/go-libp2p/p2p/http"
)

// algorandP2pHTTPProtocol defines a libp2p protocol name for algorand's http over p2p messages
const algorandP2pHTTPProtocol = "/algorand-http/1.0.0"

// HTTPServer is a wrapper around libp2phttp.Host that allows registering http handlers with path parameters.
type HTTPServer struct {
	libp2phttp.Host
	p2phttpMux              *mux.Router
	p2phttpMuxRegistrarOnce sync.Once
}

// MakeHTTPServer creates a new HTTPServer
func MakeHTTPServer(streamHost host.Host) *HTTPServer {
	httpServer := HTTPServer{
		Host:       libp2phttp.Host{StreamHost: streamHost},
		p2phttpMux: mux.NewRouter(),
	}
	return &httpServer
}

// RegisterHTTPHandler registers a http handler with a given path.
func (s *HTTPServer) RegisterHTTPHandler(path string, handler http.Handler) {
	s.p2phttpMux.Handle(path, handler)
	s.p2phttpMuxRegistrarOnce.Do(func() {
		s.Host.SetHTTPHandlerAtPath(algorandP2pHTTPProtocol, "/", s.p2phttpMux)
	})
}

// RegisterHTTPHandlerFunc registers a http handler with a given path.
func (s *HTTPServer) RegisterHTTPHandlerFunc(path string, handler func(http.ResponseWriter, *http.Request)) {
	s.p2phttpMux.HandleFunc(path, handler)
	s.p2phttpMuxRegistrarOnce.Do(func() {
		s.Host.SetHTTPHandlerAtPath(algorandP2pHTTPProtocol, "/", s.p2phttpMux)
	})
}

// MakeHTTPClient creates a http.Client that uses libp2p transport for a given protocol and peer address.
func MakeHTTPClient(addrInfo *peer.AddrInfo) (*http.Client, error) {
	clientStreamHost, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		return nil, err
	}
	logging.Base().Debugf("MakeHTTPClient made a new P2P host %s for %s", clientStreamHost.ID(), addrInfo.String())

	client := libp2phttp.Host{StreamHost: clientStreamHost}

	// Do not use client.NamespacedClient to prevent it making connection to a well-known handler
	// to make a NamespaceRoundTripper that limits to specific URL paths.
	// First, we do not want make requests when listing peers (the main MakeHTTPClient invoker).
	// Secondly, this makes unit testing easier - no need to register fake handlers.
	rt, err := client.NewConstrainedRoundTripper(*addrInfo)
	if err != nil {
		return nil, err
	}

	return &http.Client{Transport: rt}, nil
}

// MakeHTTPClientWithRateLimit creates a http.Client that uses libp2p transport for a given protocol and peer address.
func MakeHTTPClientWithRateLimit(addrInfo *peer.AddrInfo, pstore limitcaller.ConnectionTimeStore, queueingTimeout time.Duration, maxIdleConnsPerHost int) (*http.Client, error) {
	cl, err := MakeHTTPClient(addrInfo)
	if err != nil {
		return nil, err
	}
	rlrt := limitcaller.MakeRateLimitingTransportWithRoundTripper(pstore, queueingTimeout, cl.Transport, addrInfo, maxIdleConnsPerHost)
	cl.Transport = &rlrt
	return cl, nil

}
