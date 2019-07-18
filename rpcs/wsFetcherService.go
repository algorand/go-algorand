// Copyright (C) 2019 Algorand, Inc.
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

package rpcs

import (
	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

// WsFetcherService exists for the express purpose or providing a global
// handler for fetcher gossip message response types
type WsFetcherService struct {
	log      logging.Logger
	mu       deadlock.RWMutex
	fetchers map[protocol.Tag]*WsFetcher
}

func (fs *WsFetcherService) handleNetworkMsg(msg network.IncomingMessage) (out network.OutgoingMessage) {
	// route message to appropriate wsFetcher (if registered)
	fs.mu.RLock()
	f := fs.fetchers[msg.Tag]
	fs.mu.RUnlock()
	if f == nil {
		fs.log.Infof("WsFetcherService: no fetcher registered for tag (%v)", msg.Tag)
		return
	}
	return f.HandleNetworkMsg(msg)
}

// RegisterWsFetcherForTag registers the given WsFetcher for the given tag, overwriting
// any fetcher previously registered for that tag.
func (fs *WsFetcherService) RegisterWsFetcherForTag(f *WsFetcher, tag protocol.Tag) {
	fs.mu.Lock()
	fs.fetchers[tag] = f
	fs.mu.Unlock()
}

// UnregisterWsFetcherForTag clears the specified fetcher for the specified tag, if it exists.
// We force the caller to pass in the fetcher, so that they don't unintentionally close another fetcher
// that was registered before the first was closed.
func (fs *WsFetcherService) UnregisterWsFetcherForTag(f *WsFetcher, tag protocol.Tag) {
	fs.mu.Lock()
	if fs.fetchers[tag] == f {
		delete(fs.fetchers, tag)
	}
	fs.mu.Unlock()
}

// RegisterWsFetcherService creates and returns a WsFetcherService that services gossip fetcher responses
func RegisterWsFetcherService(log logging.Logger, registrar Registrar) *WsFetcherService {
	service := new(WsFetcherService)
	service.log = log
	service.fetchers = make(map[protocol.Tag]*WsFetcher)
	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.UniCatchupResTag, MessageHandler: network.HandlerFunc(service.handleNetworkMsg)},
		{Tag: protocol.UniEnsBlockResTag, MessageHandler: network.HandlerFunc(service.handleNetworkMsg)},
	}
	registrar.RegisterHandlers(handlers)
	return service
}
