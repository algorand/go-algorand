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

// This is a copy of p2p/muxer/yamux from go-libp2p but uses our yamux fork.

package p2p

import (
	"context"
	"io"
	"math"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	yamux "github.com/algorandskiy/go-yamux/v4"
)

// DefaultTransport is the default transport for libp2p connections.
var DefaultTransport *Transport

// ID is the protocol ID for yamux.
const ID = "/yamux/1.0.0"

func init() {
	config := yamux.DefaultConfig()
	// We've bumped this to 16MiB as this critically limits throughput.
	//
	// 1MiB means a best case of 10MiB/s (83.89Mbps) on a connection with
	// 100ms latency. The default gave us 2.4MiB *best case* which was
	// totally unacceptable.
	config.MaxStreamWindowSize = uint32(16 * 1024 * 1024)
	// don't spam
	config.LogOutput = io.Discard
	// We always run over a security transport that buffers internally
	// (i.e., uses a block cipher).
	config.ReadBufSize = 0
	// Effectively disable the incoming streams limit.
	// This is now dynamically limited by the resource manager.
	config.MaxIncomingStreams = math.MaxUint32
	DefaultTransport = (*Transport)(config)
}

// Transport implements mux.Multiplexer that constructs
// yamux-backed muxed connections.
type Transport yamux.Config

var _ network.Multiplexer = &Transport{}

// NewConn constructs a new MuxedConn from a net.Conn.
func (t *Transport) NewConn(nc net.Conn, isServer bool, scope network.PeerScope) (network.MuxedConn, error) {
	var newSpan func() (yamux.MemoryManager, error)
	if scope != nil {
		newSpan = func() (yamux.MemoryManager, error) { return scope.BeginSpan() }
	}

	var s *yamux.Session
	var err error
	if isServer {
		s, err = yamux.Server(nc, t.Config(), newSpan)
	} else {
		s, err = yamux.Client(nc, t.Config(), newSpan)
	}
	if err != nil {
		return nil, err
	}
	return NewMuxedConn(s), nil
}

// Config returns the yamux.Config.
func (t *Transport) Config() *yamux.Config {
	return (*yamux.Config)(t)
}

// conn implements mux.MuxedConn over yamux.Session.
type conn yamux.Session

var _ network.MuxedConn = &conn{}

// NewMuxedConn constructs a new MuxedConn from a yamux.Session.
func NewMuxedConn(m *yamux.Session) network.MuxedConn {
	return (*conn)(m)
}

// Close closes underlying yamux
func (c *conn) Close() error {
	return c.yamux().Close()
}

// IsClosed checks if yamux.Session is in closed state.
func (c *conn) IsClosed() bool {
	return c.yamux().IsClosed()
}

// OpenStream creates a new stream.
func (c *conn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	s, err := c.yamux().OpenStream(ctx)
	if err != nil {
		return nil, err
	}

	return (*stream)(s), nil
}

// AcceptStream accepts a stream opened by the other side.
func (c *conn) AcceptStream() (network.MuxedStream, error) {
	s, err := c.yamux().AcceptStream()
	return (*stream)(s), err
}

func (c *conn) yamux() *yamux.Session {
	return (*yamux.Session)(c)
}

// stream implements mux.MuxedStream over yamux.Stream.
type stream yamux.Stream

var _ network.MuxedStream = &stream{}

func (s *stream) Read(b []byte) (n int, err error) {
	n, err = s.yamux().Read(b)
	if err == yamux.ErrStreamReset {
		err = network.ErrReset
	}

	return n, err
}

func (s *stream) Write(b []byte) (n int, err error) {
	n, err = s.yamux().Write(b)
	if err == yamux.ErrStreamReset {
		err = network.ErrReset
	}

	return n, err
}

func (s *stream) Close() error {
	return s.yamux().Close()
}

func (s *stream) Reset() error {
	return s.yamux().Reset()
}

func (s *stream) CloseRead() error {
	return s.yamux().CloseRead()
}

func (s *stream) CloseWrite() error {
	return s.yamux().CloseWrite()
}

func (s *stream) SetDeadline(t time.Time) error {
	return s.yamux().SetDeadline(t)
}

func (s *stream) SetReadDeadline(t time.Time) error {
	return s.yamux().SetReadDeadline(t)
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	return s.yamux().SetWriteDeadline(t)
}

func (s *stream) yamux() *yamux.Stream {
	return (*yamux.Stream)(s)
}
