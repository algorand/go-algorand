// Copyright (C) 2019-2021 Algorand, Inc.
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
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/config"
)

const pongMessageWriteDuration = time.Second

type latencyTracker struct {
	receivedPacketCounter   uint64
	lastPingID              uint64
	lastPingSentTime        int64
	lastPingReceivedCounter uint64
	latency                 int64
	conn                    wsPeerWebsocketConn // static
	enabled                 bool                // static
	pingInterval            time.Duration       // static
}

func (lt *latencyTracker) init(conn wsPeerWebsocketConn, cfg config.Local, initialConnectionLatency time.Duration) {
	lt.conn = conn
	lt.enabled = true
	lt.latency = int64(initialConnectionLatency)
	lt.pingInterval = time.Duration(cfg.PeerPingPeriodSeconds) * time.Second
	conn.SetPingHandler(lt.pingHandler)
	conn.SetPongHandler(lt.pongHandler)
}

func (lt *latencyTracker) pingHandler(message string) error {
	err := lt.conn.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(pongMessageWriteDuration))
	if err == websocket.ErrCloseSent {
		return nil
	} else if e, ok := err.(net.Error); ok && e.Temporary() {
		return nil
	}
	return err
}

func (lt *latencyTracker) pongHandler(appData string) error {
	pongID, err := strconv.Atoi(appData)
	if err != nil {
		// todo - log the issue here.
		return nil
	}

	if uint64(pongID) != atomic.LoadUint64(&lt.lastPingID) {
		// we've sent more than one ping since; ignore this message.
		return nil
	}
	if atomic.LoadUint64(&lt.receivedPacketCounter) != lt.lastPingReceivedCounter {
		// we've received other messages since the one that we sent. The timing
		// here would not be accurate.
		return nil
	}
	lastPingSentTime := time.Unix(0, atomic.LoadInt64(&lt.lastPingSentTime))
	roundtripDuration := time.Since(lastPingSentTime)
	atomic.StoreInt64(&lt.latency, roundtripDuration.Nanoseconds())
	return nil
}

func (lt *latencyTracker) getConnectionLatency() time.Duration {
	return time.Duration(atomic.LoadInt64(&lt.latency))
}

func (lt *latencyTracker) checkPingSending(now *time.Time) error {
	if lt.enabled == false {
		return nil
	}
	if now.Sub(time.Unix(0, atomic.LoadInt64(&lt.lastPingSentTime))) < lt.pingInterval {
		return nil
	}
	lastPingID := atomic.AddUint64(&lt.lastPingID, 1)
	err := lt.conn.WriteControl(websocket.PingMessage, []byte(strconv.Itoa(int(lastPingID))), time.Now().Add(pongMessageWriteDuration))
	if err == websocket.ErrCloseSent {
		return nil
	} else if e, ok := err.(net.Error); ok && e.Temporary() {
		return nil
	}
	if err != nil {
		return err
	}
	atomic.StoreInt64(&lt.lastPingSentTime, now.UnixNano())
	atomic.StoreUint64(&lt.lastPingReceivedCounter, atomic.LoadUint64(&lt.receivedPacketCounter))
	return nil
}

func (lt *latencyTracker) increaseReceivedCounter() {
	atomic.AddUint64(&lt.receivedPacketCounter, 1)
}
