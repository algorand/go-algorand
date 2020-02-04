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
	"context"
	"net"
	"net/http"
	"time"
)

// RateLimitedTransport is a wrapper around the http.Transport that overrides the Dial and DialContext functions.
// It limits the rate of the outgoing connections to comply with connectionsRateLimitingCount
type RateLimitedTransport struct {
	phonebook   *MultiPhonebook
	innerDialer net.Dialer
	*http.Transport
}

// Dial redirects the call to MyTransport.DialContext
func (rlt *RateLimitedTransport) Dial(network, address string) (net.Conn, error) {
	return rlt.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
// It wraps around the http.Transport.DialContext to limit the outgoing connection rate
// It waits if needed not to exceed connectionsRateLimitingCount.
func (rlt *RateLimitedTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var waitTime time.Duration
	var provisionalTime time.Time

	for {
		_, waitTime, provisionalTime = rlt.phonebook.GetConnectionWaitTime(address)
		if waitTime == 0 {
			break // break out of the loop and proceed to the connection
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(waitTime):
		}
	}
	conn, err := rlt.innerDialer.DialContext(ctx, network, address)
	rlt.phonebook.UpdateConnectionTime(address, provisionalTime)

	return conn, err
}
