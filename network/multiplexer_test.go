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

package network

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func makeSignedTxnMsg() IncomingMessage {
	return IncomingMessage{Sender: &wsPeer{}, Tag: protocol.TxnTag, Data: []byte("I am a signed transaction")}
}

func makeVoteMsg() IncomingMessage {
	return IncomingMessage{Sender: &wsPeer{}, Tag: protocol.AgreementVoteTag, Data: []byte("I am an agreement vote message")}
}

// Message handler that remembers the last message it handled
type testHandler struct {
	msg *IncomingMessage
}

func (th *testHandler) Reset() {
	th.msg = nil
}
func (th *testHandler) Handle(msg IncomingMessage) OutgoingMessage {
	th.msg = &msg
	return OutgoingMessage{}
}
func (th *testHandler) SawMsg(msg IncomingMessage) bool {
	if th.msg == nil {
		return false
	}
	return bytes.Equal(th.msg.Data, msg.Data) && (th.msg.Sender == msg.Sender)
}

func TestMultiplexer(t *testing.T) {
	m := MakeMultiplexer(logging.TestingLog(t))
	handler := &testHandler{}

	// Handler shouldn't be called before it is registered
	msg1 := makeSignedTxnMsg()
	_ = m.Handle(msg1)
	if handler.SawMsg(msg1) {
		t.Errorf("Handler was called before we registered it")
	}

	// Registering our handler should succeed
	m.RegisterHandlers([]TaggedMessageHandler{{protocol.TxnTag, handler}})

	// Can't register two handlers for the same typetag
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		m := MakeMultiplexer(logging.TestingLog(t))
		m.RegisterHandlers([]TaggedMessageHandler{{protocol.TxnTag, handler}, {protocol.TxnTag, handler}})

	}()
	require.True(t, panicked)
	panicked = false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		m := MakeMultiplexer(logging.TestingLog(t))
		m.RegisterHandlers([]TaggedMessageHandler{{protocol.TxnTag, handler}})
		m.RegisterHandlers([]TaggedMessageHandler{{protocol.TxnTag, handler}})

	}()
	require.True(t, panicked)

	// Handler should be called on SignedTxn messages now that we've registered it
	msg2 := makeSignedTxnMsg()
	_ = m.Handle(msg2)
	if !handler.SawMsg(msg2) {
		t.Errorf("Handler was not called on a SignedTxn it was registered to handle")
		t.Errorf("handledMsg: %v", handler.msg)
		t.Errorf("msg2: %v", msg2)
	}
	handler.Reset()

	// Handler should not be called on tags it isn't registered for
	msg3 := makeVoteMsg()
	_ = m.Handle(msg3)
	require.False(t, handler.SawMsg(msg3))
	handler.Reset()

	// After deregistering, should not get any more incoming messages
	m.ClearHandlers([]Tag{})
	msg5 := makeSignedTxnMsg()
	m.Handle(msg5)
	require.False(t, handler.SawMsg(msg5))
	handler.Reset()
}
