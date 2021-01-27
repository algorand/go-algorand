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
	"sync/atomic"

	"github.com/algorand/go-algorand/logging"
)

// Multiplexer is a message handler that sorts incoming messages by Tag and passes
// them along to the relevant message handler for that type of message.
type Multiplexer struct {
	msgHandlers atomic.Value // stores map[Tag]MessageHandler, an immutable map.

	log logging.Logger
}

// MakeMultiplexer creates an empty Multiplexer
func MakeMultiplexer(log logging.Logger) *Multiplexer {
	m := &Multiplexer{
		log: log,
	}
	m.ClearHandlers([]Tag{}) // allocate the map
	return m
}

// getHandlersMap retrieves the handlers map.
func (m *Multiplexer) getHandlersMap() map[Tag]MessageHandler {
	handlersVal := m.msgHandlers.Load()
	if handlers, valid := handlersVal.(map[Tag]MessageHandler); valid {
		return handlers
	}
	return nil
}

// Retrives the handler for the given message Tag from the handlers array while taking a read lock.
func (m *Multiplexer) getHandler(tag Tag) (MessageHandler, bool) {
	if handlers := m.getHandlersMap(); handlers != nil {
		handler, ok := handlers[tag]
		return handler, ok
	}
	return nil, false
}

// Handle is the "input" side of the multiplexer. It dispatches the message to the previously defined handler.
func (m *Multiplexer) Handle(msg IncomingMessage) OutgoingMessage {
	handler, ok := m.getHandler(msg.Tag)

	if ok {
		outmsg := handler.Handle(msg)
		return outmsg
	}
	return OutgoingMessage{}
}

// RegisterHandlers registers the set of given message handlers.
func (m *Multiplexer) RegisterHandlers(dispatch []TaggedMessageHandler) {
	mp := make(map[Tag]MessageHandler)
	if existingMap := m.getHandlersMap(); existingMap != nil {
		for k, v := range existingMap {
			mp[k] = v
		}
	}
	for _, v := range dispatch {
		if _, has := mp[v.Tag]; has {
			m.log.Panicf("Already registered a handler for tag %v", v.Tag)
		}
		mp[v.Tag] = v.MessageHandler
	}
	m.msgHandlers.Store(mp)
}

// ClearHandlers deregisters all the existing message handlers other than the one provided in the excludeTags list
func (m *Multiplexer) ClearHandlers(excludeTags []Tag) {
	if len(excludeTags) == 0 {
		m.msgHandlers.Store(make(map[Tag]MessageHandler))
		return
	}

	// convert into map, so that we can exclude duplicates.
	excludeTagsMap := make(map[Tag]bool)
	for _, tag := range excludeTags {
		excludeTagsMap[tag] = true
	}

	currentHandlersMap := m.getHandlersMap()
	newMap := make(map[Tag]MessageHandler, len(excludeTagsMap))
	for tag, handler := range currentHandlersMap {
		if excludeTagsMap[tag] {
			newMap[tag] = handler
		}
	}

	m.msgHandlers.Store(newMap)
}
