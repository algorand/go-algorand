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

package addr

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/multiformats/go-multiaddr"
)

var errURLNoHost = errors.New("could not parse a host from url")

var errURLColonHost = errors.New("host name starts with a colon")

// HostColonPortPattern matches "^[-a-zA-Z0-9.]+:\\d+$" e.g. "foo.com.:1234"
var HostColonPortPattern = regexp.MustCompile(`^[-a-zA-Z0-9.]+:\d+$`)

// ParseHostOrURL handles "host:port" or a full URL.
// Standard library net/url.Parse chokes on "host:port".
func ParseHostOrURL(addr string) (*url.URL, error) {
	// If the entire addr is "host:port" grab that right away.
	// Don't try url.Parse() because that will grab "host:" as if it were "scheme:"
	if HostColonPortPattern.MatchString(addr) {
		return &url.URL{Scheme: "http", Host: addr}, nil
	}
	parsed, err := url.Parse(addr)
	if err == nil {
		if parsed.Host == "" {
			return nil, errURLNoHost
		}
		return parsed, nil
	}
	if strings.HasPrefix(addr, "http:") || strings.HasPrefix(addr, "https:") || strings.HasPrefix(addr, "ws:") || strings.HasPrefix(addr, "wss:") || strings.HasPrefix(addr, "://") || strings.HasPrefix(addr, "//") {
		return parsed, err
	}
	// This turns "[::]:4601" into "http://[::]:4601" which url.Parse can do
	parsed, e2 := url.Parse("http://" + addr)
	if e2 == nil {
		// https://datatracker.ietf.org/doc/html/rfc1123#section-2
		// first character is relaxed to allow either a letter or a digit
		if parsed.Host[0] == ':' && (len(parsed.Host) < 2 || parsed.Host[1] != ':') {
			return nil, errURLColonHost
		}
		return parsed, nil
	}
	return parsed, err /* return original err, not our prefix altered try */
}

// IsMultiaddr returns true if the provided string is a valid multiaddr.
func IsMultiaddr(addr string) bool {
	if strings.HasPrefix(addr, "/") && !strings.HasPrefix(addr, "//") { // multiaddr starts with '/' but not '//' which is possible for scheme relative URLS
		_, err := multiaddr.NewMultiaddr(addr)
		return err == nil
	}
	return false
}

// ParseHostOrURLOrMultiaddr returns an error if it could not parse the provided
// string as a valid "host:port", full URL, or multiaddr. If no error, it returns
// a host:port address, or a multiaddr.
func ParseHostOrURLOrMultiaddr(addr string) (string, error) {
	if strings.HasPrefix(addr, "/") && !strings.HasPrefix(addr, "//") { // multiaddr starts with '/' but not '//' which is possible for scheme relative URLS
		_, err := multiaddr.NewMultiaddr(addr)
		return addr, err
	}
	url, err := ParseHostOrURL(addr)
	if err != nil {
		return "", err
	}
	return url.Host, nil
}
