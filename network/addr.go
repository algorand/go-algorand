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
	"path"
	"strings"

	"github.com/algorand/go-algorand/network/addr"
)

// addrToGossipAddr parses host:port or a URL and returns the URL to the websocket interface at that address.
func (wn *WebsocketNetwork) addrToGossipAddr(a string) (string, error) {
	parsedURL, err := addr.ParseHostOrURL(a)
	if err != nil {
		wn.log.Warnf("could not parse addr %#v: %s", a, err)
		return "", errBadAddr
	}
	parsedURL.Scheme = websocketsScheme[parsedURL.Scheme]
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "ws"
	}
	parsedURL.Path = strings.Replace(path.Join(parsedURL.Path, GossipNetworkPath), "{genesisID}", wn.GenesisID, -1)
	return parsedURL.String(), nil
}
