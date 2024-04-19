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

// This is a simple reverse proxy for websocket connections. It is used to to test
// ws network behavior when UseXForwardedForAddressField is enabled.
// Not suitable for production use.
package network

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/algorand/go-algorand/network/addr"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/websocket"
	"github.com/stretchr/testify/require"
)

var testProxyUpgrader = websocket.Upgrader{
	ReadBufferSize:    4096,
	WriteBufferSize:   4096,
	EnableCompression: false,
}

var testProxyDialer = net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
	DualStack: true,
}

var testProxyWebsocketDialer = websocket.Dialer{
	HandshakeTimeout:  45 * time.Second,
	EnableCompression: false,
	NetDialContext:    testProxyDialer.DialContext,
	NetDial:           testProxyDialer.Dial,
	MaxHeaderSize:     wsMaxHeaderBytes,
}

type websocketProxy struct {
	upstream              string
	overrideXForwardedFor string
}

// ServeHTTP implements http.Handler
func (w *websocketProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// copy all but upgrade headers otherwise Dial complains about duplicate headers
	headers := http.Header{}
	for k, v := range request.Header {
		// filter out upgrade headers since Upgrader will add them
		if k == "Sec-Websocket-Key" || k == "Sec-Websocket-Version" || k == "Connection" || k == "Upgrade" {
			continue
		}
		headers[k] = v
	}

	// set X-Forwarded-For
	url, err := addr.ParseHostOrURL(request.RemoteAddr)
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	if w.overrideXForwardedFor != "" {
		headers.Set("X-Forwarded-For", w.overrideXForwardedFor)
	} else {
		headers.Set("X-Forwarded-For", url.Hostname())
	}

	upURL := *request.URL
	upURL.Host = w.upstream
	upURL.Scheme = "ws"

	// dial upstream
	upstreamConn, upResp, err := testProxyWebsocketDialer.Dial(upURL.String(), headers)
	if err != nil {
		msg := fmt.Sprintf("websocketProxy: error dialing upstream %s: %s", upURL.String(), err.Error())
		if upResp != nil {
			msg = fmt.Sprintf("%s: %v", msg, *upResp)
		}
		http.Error(response, msg, http.StatusInternalServerError)
		return
	}
	defer upstreamConn.Close()

	// upgeade the client
	remoteConn, err := testProxyUpgrader.Upgrade(response, request, upResp.Header)
	if err != nil {
		http.Error(response, "websocketProxy: error upgrading connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	defer remoteConn.Close()

	remoteConn.SetReadLimit(MaxMessageLength)
	upstreamConn.SetReadLimit(MaxMessageLength)

	errCh := make(chan error, 1)
	go w.forward(remoteConn, upstreamConn, errCh)
	go w.forward(upstreamConn, remoteConn, errCh)

	err = <-errCh
	if e, ok := err.(*websocket.CloseError); !ok {
		// calling http.Error causes "response.WriteHeader on hijacked connection" error
		fmt.Printf("websocketProxy: closing error forwarding connection: %s\n", err.Error())
	} else if e.Code != websocket.CloseNormalClosure {
		fmt.Printf("websocketProxy: closing error forwarding connection: %s\n", err.Error())
	}
}

func (w *websocketProxy) forward(dst, src *websocket.Conn, errCh chan error) {
	for {
		msgType, msg, err := src.ReadMessage()
		if err != nil {
			errCh <- err
			return
		}
		err = dst.WriteMessage(msgType, msg)
		if err != nil {
			errCh <- err
			return
		}
	}
}

// TestWebsocketProxy checks the websocket proxy implementation:
// it forwards messages ands adds X-Forwarded-For header
func TestWebsocketProxy(t *testing.T) {
	partitiontest.PartitionTest(t)

	var headerChecker func(headers http.Header) // define below when all addresses are known

	// setup the upstream server
	upstreamAddr := "127.0.0.1:"
	upstreamMux := http.NewServeMux()
	upstreamMux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {})
	upstreamMux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		// handler returns the same message it receives with a prefix 'pong:'
		t.Logf("upsream received connection from %s\n", r.RemoteAddr)
		headerChecker(r.Header)

		conn, err := testProxyUpgrader.Upgrade(w, r, nil)
		require.NoError(t, err)
		conn.SetReadLimit(2 * 1024)
		messageType, p, err := conn.ReadMessage()
		require.NoError(t, err)
		msg := append([]byte("pong:"), p...)
		conn.WriteMessage(messageType, msg)
		require.NoError(t, err)
	})
	upstreamListener, err := net.Listen("tcp", upstreamAddr)
	require.NoError(t, err)
	upstreamAddr = upstreamListener.Addr().String()
	upstreamSrv := &http.Server{Addr: upstreamAddr, Handler: upstreamMux}
	go upstreamSrv.Serve(upstreamListener)

	// wait upstream to be ready
	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + upstreamAddr + "/status")
		if err != nil {
			return false
		}
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 100*time.Millisecond)

	// setup the proxy
	wsProxy := &websocketProxy{upstreamAddr, ""}
	wsProxyMux := http.NewServeMux()
	wsProxyMux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {})
	wsProxyMux.Handle("/ws", wsProxy)
	wsProxyListener, err := net.Listen("tcp", "[::1]:")
	require.NoError(t, err)

	wsProxyAddr := wsProxyListener.Addr().String()
	wsProxySrv := &http.Server{Addr: wsProxyAddr, Handler: wsProxyMux}
	go wsProxySrv.Serve(wsProxyListener)

	checked := false
	headerChecker = func(headers http.Header) {
		hostname, _, err := net.SplitHostPort(wsProxyAddr)
		require.NoError(t, err)
		require.Contains(t, headers, ("X-Forwarded-For"))
		require.Equal(t, hostname, headers.Get("X-Forwarded-For"))
		checked = true
	}

	// wait ws proxy to be ready
	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + wsProxyAddr + "/status")
		if err != nil {
			return false
		}
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 100*time.Millisecond)

	t.Logf("upstream addr: %s", upstreamAddr)
	t.Logf("ws proxy addr: %s", wsProxyAddr)

	// now send data through the proxy
	conn, resp, err := testProxyWebsocketDialer.Dial("ws://"+wsProxyAddr+"/ws", nil)
	var errMsg string
	if err != nil && resp != nil {
		b, err0 := io.ReadAll(resp.Body)
		require.NoError(t, err0)
		errMsg = fmt.Sprintf("error dialing proxy: %v, body: %s", resp, b)
	}
	require.NoError(t, err, errMsg)
	t.Logf("connected to %s", conn.RemoteAddr().String())

	conn.SetReadLimit(2 * 1024)
	msg := "ping"
	conn.WriteMessage(websocket.TextMessage, []byte(msg))
	require.NoError(t, err)
	messageType, p, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.TextMessage, messageType)
	require.Equal(t, "pong:"+msg, string(p))

	conn.Close()
	err = upstreamSrv.Shutdown(context.Background())
	require.NoError(t, err)
	err = wsProxySrv.Shutdown(context.Background())
	require.NoError(t, err)

	// ensure the header was checked
	require.True(t, checked)
}

func TestWebsocketProxyWsNet(t *testing.T) {
	partitiontest.PartitionTest(t)

	// upstream node
	netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
	netA.requestsTracker.config.UseXForwardedForAddressField = "X-Forwarded-For"
	netA.Start()
	defer netA.Stop()
	addrA, ok := netA.Address()
	require.True(t, ok)
	gossipA, err := netA.addrToGossipAddr(addrA)
	require.NoError(t, err)

	parsedA, err := addr.ParseHostOrURL(gossipA)
	require.NoError(t, err)

	// setup the proxy
	// use a fake address since all nodes are on the same machine/localhost
	fakeXForwardedFor := "169.254.1.1"
	wsProxy := &websocketProxy{parsedA.Host, fakeXForwardedFor}
	wsProxyMux := http.NewServeMux()
	wsProxyMux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {})
	wsProxyMux.Handle(parsedA.Path, wsProxy)
	wsProxyListener, err := net.Listen("tcp", "[::1]:")
	require.NoError(t, err)

	wsProxyAddr := wsProxyListener.Addr().String()
	wsProxySrv := &http.Server{Addr: wsProxyAddr, Handler: wsProxyMux}
	go wsProxySrv.Serve(wsProxyListener)
	defer wsProxySrv.Shutdown(context.Background())

	// wait ws proxy to be ready
	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + wsProxyAddr + "/status")
		if err != nil {
			return false
		}
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 100*time.Millisecond)

	netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
	netB.Start()
	defer netB.Stop()
	addrB, ok := netB.Address()
	require.True(t, ok)

	t.Logf("upstream addr: %s", addrA)
	t.Logf("ws proxy addr: %s", wsProxyAddr)
	t.Logf("client netB addr: %s", addrB)

	require.Equal(t, 0, len(netA.GetPeers(PeersConnectedIn)))
	require.Equal(t, 0, len(netA.GetPeers(PeersConnectedOut)))
	require.Equal(t, 0, len(netB.GetPeers(PeersConnectedIn)))
	require.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))

	wsProxyGossip, ok := netB.tryConnectReserveAddr(wsProxyAddr)
	require.True(t, ok)

	netB.wg.Add(1)
	netB.tryConnect(wsProxyAddr, wsProxyGossip)

	require.Eventually(t, func() bool {
		return len(netB.GetPeers(PeersConnectedOut)) == 1
	}, 5*time.Second, 10*time.Millisecond)

	require.Equal(t, 1, len(netA.GetPeers(PeersConnectedIn)))
	require.Equal(t, 0, len(netA.GetPeers(PeersConnectedOut)))
	require.Equal(t, 0, len(netB.GetPeers(PeersConnectedIn)))
	require.Equal(t, 1, len(netB.GetPeers(PeersConnectedOut)))

	// get peerB from the upstream node (netA)
	// and ensure it has the expected origin/routing address as set by the proxy
	peerB := netA.peers[0]
	require.NotEmpty(t, peerB.originAddress)
	require.Equal(t, fakeXForwardedFor, peerB.originAddress)
	require.NotEqual(t, peerB.RoutingAddr(), peerB.ipAddr())
	fakeXForwardedForParsed := net.ParseIP(fakeXForwardedFor)
	require.NotEqual(t, fakeXForwardedForParsed, peerB.RoutingAddr())
}
