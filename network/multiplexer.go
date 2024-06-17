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

package network

import (
	"fmt"
	"sync/atomic"
)

// Multiplexer is a message handler that sorts incoming messages by Tag and passes
// them along to the relevant message handler for that type of message.
type Multiplexer struct {
	msgHandlers   atomic.Value // stores map[Tag]MessageHandler, an immutable map.
	msgProcessors atomic.Value // stores map[Tag]MessageProcessor, an immutable map.
}

// MakeMultiplexer creates an empty Multiplexer
func MakeMultiplexer() *Multiplexer {
	m := &Multiplexer{}
	m.ClearHandlers(nil)   // allocate the map
	m.ClearProcessors(nil) // allocate the map
	return m
}

// getMap retrieves a typed map from an atomic.Value.
func getMap[T any](source *atomic.Value) map[Tag]T {
	mp := source.Load()
	if handlers, valid := mp.(map[Tag]T); valid {
		return handlers
	}
	return nil
}

// getHandlersMap retrieves the handlers map.
func (m *Multiplexer) getHandlersMap() map[Tag]MessageHandler {
	return getMap[MessageHandler](&m.msgHandlers)
}

// getProcessorsMap retrieves the processors map.
func (m *Multiplexer) getProcessorsMap() map[Tag]MessageProcessor {
	return getMap[MessageProcessor](&m.msgHandlers)
}

// Retrieves the handler for the given message Tag from the given value while.
func getHandler[T any](source *atomic.Value, tag Tag) (T, bool) {
	if handlers := getMap[T](source); handlers != nil {
		handler, ok := handlers[tag]
		return handler, ok
	}
	var empty T
	return empty, false
}

// Retrieves the handler for the given message Tag from the handlers array.
func (m *Multiplexer) getHandler(tag Tag) (MessageHandler, bool) {
	return getHandler[MessageHandler](&m.msgHandlers, tag)
}

// Retrieves the processor for the given message Tag from the processors array.
func (m *Multiplexer) getProcessor(tag Tag) (MessageProcessor, bool) {
	return getHandler[MessageProcessor](&m.msgProcessors, tag)
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

// Validate is an alternative "input" side of the multiplexer. It dispatches the message to the previously defined validator.
func (m *Multiplexer) Validate(msg IncomingMessage) ValidatedMessage {
	handler, ok := m.getProcessor(msg.Tag)

	if ok {
		outmsg := handler.Validate(msg)
		return outmsg
	}
	return ValidatedMessage{}
}

// Process is the second step of message handling after validation. It dispatches the message to the previously defined processor.
func (m *Multiplexer) Process(msg ValidatedMessage) OutgoingMessage {
	handler, ok := m.getProcessor(msg.Tag)

	if ok {
		outmsg := handler.Handle(msg)
		return outmsg
	}
	return OutgoingMessage{}
}

func register[T any](target *atomic.Value, dispatch []taggedMessageDispatcher[T]) {
	mp := make(map[Tag]T)
	if existingMap := getMap[T](target); existingMap != nil {
		for k, v := range existingMap {
			mp[k] = v
		}
	}
	for _, v := range dispatch {
		if _, has := mp[v.Tag]; has {
			panic(fmt.Sprintf("Already registered a handler for tag %v", v.Tag))
		}
		mp[v.Tag] = v.Dispatcher
	}
	target.Store(mp)
}

// RegisterHandlers registers the set of given message handlers.
func (m *Multiplexer) RegisterHandlers(dispatch []TaggedMessageHandler) {
	register[MessageHandler](&m.msgHandlers, dispatch)
}

// RegisterProcessors registers the set of given message handlers.
func (m *Multiplexer) RegisterProcessors(dispatch []TaggedMessageProcessor) {
	register[MessageProcessor](&m.msgProcessors, dispatch)
}

func clear[T any](target *atomic.Value, excludeTags []Tag) {
	if len(excludeTags) == 0 {
		target.Store(make(map[Tag]T))
		return
	}

	// convert into map, so that we can exclude duplicates.
	excludeTagsMap := make(map[Tag]bool)
	for _, tag := range excludeTags {
		excludeTagsMap[tag] = true
	}

	currentMap := getMap[T](target)
	newMap := make(map[Tag]T, len(excludeTagsMap))
	for tag, handler := range currentMap {
		if excludeTagsMap[tag] {
			newMap[tag] = handler
		}
	}

	target.Store(newMap)
}

// ClearHandlers deregisters all the existing message handlers other than the one provided in the excludeTags list
func (m *Multiplexer) ClearHandlers(excludeTags []Tag) {
	clear[MessageHandler](&m.msgHandlers, excludeTags)
}

// ClearProcessors deregisters all the existing message handlers other than the one provided in the excludeTags list
func (m *Multiplexer) ClearProcessors(excludeTags []Tag) {
	clear[MessageProcessor](&m.msgProcessors, excludeTags)
}
