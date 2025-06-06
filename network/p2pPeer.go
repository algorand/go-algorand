// Copyright (C) 2019-2025 Algorand, Inc.
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

package network

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/websocket"

	"github.com/libp2p/go-libp2p/core/network"
	yamux "github.com/libp2p/go-yamux/v4"
	mnet "github.com/multiformats/go-multiaddr/net"
)

type wsPeerConnP2P struct {
	stream network.Stream
}

func (c *wsPeerConnP2P) RemoteAddrString() string {
	return c.stream.Conn().RemoteMultiaddr().String()
}

func (c *wsPeerConnP2P) NextReader() (int, io.Reader, error) {
	// read length
	var lenbuf [4]byte
	_, err := io.ReadFull(c.stream, lenbuf[:])
	if err != nil {
		return 0, nil, err
	}
	msglen := binary.BigEndian.Uint32(lenbuf[:])
	if msglen > MaxMessageLength {
		return 0, nil, fmt.Errorf("message too long: %d", msglen)
	}
	// return io.Reader that only reads the next msglen bytes
	return websocket.BinaryMessage, io.LimitReader(c.stream, int64(msglen)), nil
}

func (c *wsPeerConnP2P) WriteMessage(_ int, buf []byte) error {
	// simple message framing:
	// 1. write encoding of the length
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(buf)))
	_, err := c.stream.Write(lenbuf[:])
	if err != nil {
		return err
	}
	// 2. write message
	_, err = c.stream.Write(buf)
	return err
}

// Do nothing for now since this doesn't actually close the connection just sends the close message
func (c *wsPeerConnP2P) CloseWithMessage([]byte, time.Time) error {
	return nil
}

func (c *wsPeerConnP2P) SetReadLimit(int64) {}

func (c *wsPeerConnP2P) CloseWithoutFlush() (err error) {
	err = c.stream.Reset()
	defer func() {
		err0 := c.stream.Conn().Close()
		if err == nil {
			err = err0
		}
	}()
	if err != nil && err != yamux.ErrStreamClosed && err != yamux.ErrSessionShutdown && err != yamux.ErrStreamReset {
		return err
	}
	return nil
}

func (c *wsPeerConnP2P) UnderlyingConn() net.Conn { return nil }

func (c *wsPeerConnP2P) RemoteAddr() net.Addr {
	netaddr, err := mnet.ToNetAddr(c.stream.Conn().RemoteMultiaddr())
	if err != nil {
		logging.Base().Errorf("Error converting multiaddr to netaddr: %v", err)
	}
	return netaddr
}
