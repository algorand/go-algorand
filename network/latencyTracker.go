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
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/algorand/websocket"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
)

const pongMessageWriteDuration = time.Second
const pingMessageWriteDuration = time.Second

var errInvalidPongMessageContent = errors.New("invalid pong message content")
var errInvalidPingMessageContent = errors.New("invalid ping message content")

// latencyTracker works in conjuction with the wspeer in measuring the
// communication latency over the websocket connection.
type latencyTracker struct {
	// receivedPacketCounter is a counter for all incoming messages
	// placed here to be aligned with 64bit address.
	receivedPacketCounter uint64
	// latency is the effective latency of the connection.
	// placed here to be aligned with 64bit address.
	latency int64

	// lastPingSentTime is the timestamp at which we last sent a message.
	// this variable is only touched by checkPingSending, and therefore doesn't
	// need to be syncronized. The "clone" of this variable lastPingSentTimeSynced,
	// is being used by both the checkPingSending as well as by the pongHandler
	// and therefore require syncronization.
	lastPingSentTime int64

	// lastPingMu synchronize the protected variables that might be modified across
	// the checkPingSending and the pongHandler.
	lastPingMu deadlock.Mutex
	// lastPingID is the last ping ID, a monotonic growing number used to ensure
	// that the pong message we've receive corresponds to the latest ping message
	// that we've sent.
	lastPingID uint64
	// lastPingReceivedCounter stores message counter at the time we sent the ping.
	// In order to ensure the timing accuracy, we want to have no other messages
	// being exchanged. This, of course, would only delay the ping-pong until a
	// better measurement could be taken.
	lastPingReceivedCounter uint64
	// lastPingSentTimeSynced, as stated above, is the syncronized version of lastPingSentTime.
	// it is used only in the case where we end up sending the ping message.
	lastPingSentTimeSynced int64

	// static variables
	// ( doesn't get changed after init, hence, no syncronization needed )

	// conn is the underlying connection object.
	conn wsPeerWebsocketConn
	// enabled indicates whether the pingpong is currently enabled or not.
	enabled bool
	// pingInterval is the max interval at which the client would send ping messages.
	pingInterval time.Duration
}

func (lt *latencyTracker) init(conn wsPeerWebsocketConn, cfg config.Local, initialConnectionLatency time.Duration) {
	lt.conn = conn
	lt.enabled = cfg.PeerPingPeriodSeconds > 0 && cfg.EnablePingHandler
	lt.latency = int64(initialConnectionLatency)
	lt.pingInterval = time.Duration(cfg.PeerPingPeriodSeconds) * time.Second
	conn.SetPingHandler(lt.pingHandler)
	conn.SetPongHandler(lt.pongHandler)
}

func (lt *latencyTracker) pingHandler(message string) error {
	if _, err := strconv.Atoi(message); err != nil {
		return errInvalidPingMessageContent
	}
	err := lt.conn.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(pongMessageWriteDuration))
	if err == websocket.ErrCloseSent {
		return nil
	} else if e, ok := err.(net.Error); ok && e.Temporary() {
		return nil
	}
	return err
}

func (lt *latencyTracker) pongHandler(message string) error {
	pongID, err := strconv.Atoi(message)
	if err != nil {
		return errInvalidPongMessageContent
	}

	lt.lastPingMu.Lock()
	defer lt.lastPingMu.Unlock()

	if uint64(pongID) != lt.lastPingID {
		// we've sent more than one ping since; ignore this message.
		return nil
	}
	if lt.receivedPacketCounter != lt.lastPingReceivedCounter {
		// we've received other messages since the one that we sent. The timing
		// here would not be accurate.
		return nil
	}
	lastPingSentTime := time.Unix(0, lt.lastPingSentTimeSynced)
	roundtripDuration := time.Since(lastPingSentTime)
	atomic.StoreInt64(&lt.latency, roundtripDuration.Nanoseconds())
	return nil
}

func (lt *latencyTracker) getConnectionLatency() time.Duration {
	return time.Duration(atomic.LoadInt64(&lt.latency))
}

func (lt *latencyTracker) checkPingSending(now *time.Time) error {
	if !lt.enabled {
		return nil
	}
	if now.Sub(time.Unix(0, lt.lastPingSentTime)) < lt.pingInterval {
		return nil
	}

	// it looks like it's time to send a ping :
	lt.lastPingMu.Lock()
	defer lt.lastPingMu.Unlock()

	lt.lastPingID++
	err := lt.conn.WriteControl(websocket.PingMessage, []byte(strconv.Itoa(int(lt.lastPingID))), now.Add(pingMessageWriteDuration))
	if err == websocket.ErrCloseSent {
		return nil
	} else if e, ok := err.(net.Error); ok && e.Temporary() {
		return nil
	}
	if err != nil {
		return err
	}
	lt.lastPingSentTimeSynced = now.UnixNano()
	lt.lastPingReceivedCounter = atomic.LoadUint64(&lt.receivedPacketCounter)
	lt.lastPingSentTime = lt.lastPingSentTimeSynced
	return nil
}

func (lt *latencyTracker) increaseReceivedCounter() {
	atomic.AddUint64(&lt.receivedPacketCounter, 1)
}
