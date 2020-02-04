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
	"net/http"
	"net"
<<<<<<< HEAD
<<<<<<< HEAD
	"time"
=======
>>>>>>> adding dialer.
=======
	"time"
>>>>>>> minor fixes
)

// Dialer establish tcp-level connection with the destination
type Dialer struct {
	phonebook   *MultiPhonebook
	innerDialer net.Dialer
}

// Dial connects to the address on the named network.
<<<<<<< HEAD
<<<<<<< HEAD
// It waits if needed not to exceed connectionsRateLimitingCount.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
// It waits if needed not to exceed connectionsRateLimitingCount.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var waitTime time.Duration
<<<<<<< HEAD
	var provisionalTime time.Time

	for {
		_, waitTime, provisionalTime = d.phonebook.GetConnectionWaitTime(address)
		if waitTime == 0 {
			break // break out of the loop and proceed to the connection
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(waitTime):
		}
	}
	conn, err := d.innerDialer.DialContext(ctx, network, address)
	d.phonebook.UpdateConnectionTime(address, provisionalTime)

	return conn, err
=======
=======
// It waits if needed not to exceed connectionsRateLimitingCount.
>>>>>>> Taking care of the lock triggering deadlock detection.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
// It waits if needed not to exceed connectionsRateLimitingCount.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
<<<<<<< HEAD
<<<<<<< HEAD
	return d.innerDialer.DialContext(ctx, network, address)
>>>>>>> adding dialer.
=======

	_, _, provisionalTime := d.phonebook.WaitForConnectionTime(address)
=======
	var waitTime time.Duration		
=======
>>>>>>> minor fixes
	var provisionalTime time.Time

	for {
		_, waitTime, provisionalTime = d.phonebook.GetConnectionWaitTime(address)
		if waitTime == 0 {
			break // break out of the loop and proceed to the connection
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(waitTime):
		}
	}
>>>>>>> Taking care of the lock triggering deadlock detection.
	conn, err := d.innerDialer.DialContext(ctx, network, address)
	d.phonebook.UpdateConnectionTime(address, provisionalTime)

	return conn, err
>>>>>>> DRAFT: using channel to offload the mutex.
}

// MyTransport is a wrapper around the http.Transport that overrides the Dial and DialContext functions. 
type MyTransport struct {
	myDialer *Dialer
	*http.Transport
}

// Dial redirects the call to MyTransport.DialContext
func (mt *MyTransport) Dial(network, addr string) (net.Conn, error) {
	return mt.myDialer.Dial(network, addr)
}

// DialContext wrapps around the http.Transport.DialContext function to perform connection limiting
func (mt *MyTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return mt.myDialer.DialContext(ctx, network, addr)
}
