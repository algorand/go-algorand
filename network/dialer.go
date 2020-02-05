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
<<<<<<< HEAD:network/rateLimitedTransport.go
<<<<<<< HEAD:network/dialer.go
<<<<<<< HEAD
<<<<<<< HEAD
=======
	"net/http"
>>>>>>> Adding RateLimitedTransport to wrap around the http.Transport:network/rateLimitedTransport.go
	"time"
=======
>>>>>>> adding dialer.
=======
	"time"
>>>>>>> minor fixes
=======
	"time"

	"fmt"
	"os"
	"runtime/debug"
>>>>>>> Separating Dialer from Transport, initializing the Dialer and Transport params (timeout, etc):network/dialer.go
)

// Dialer establish tcp-level connection with the destination
type Dialer struct {
	phonebook   *MultiPhonebook
	innerDialer net.Dialer
}

<<<<<<< HEAD:network/rateLimitedTransport.go
<<<<<<< HEAD:network/dialer.go
// Dial connects to the address on the named network.
<<<<<<< HEAD
<<<<<<< HEAD
// It waits if needed not to exceed connectionsRateLimitingCount.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
=======
// Dial redirects the call to MyTransport.DialContext
func (rlt *RateLimitedTransport) Dial(network, address string) (net.Conn, error) {
	return rlt.DialContext(context.Background(), network, address)
>>>>>>> Adding RateLimitedTransport to wrap around the http.Transport:network/rateLimitedTransport.go
=======
// Dial connects to the address on the named network.
// It waits if needed not to exceed connectionsRateLimitingCount.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
>>>>>>> Separating Dialer from Transport, initializing the Dialer and Transport params (timeout, etc):network/dialer.go
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
		fmt.Fprintf(os.Stderr, "xxxsss Waittime: %d Addr: %s\n", waitTime, address)
		debug.PrintStack()
		if waitTime == 0 {
			break // break out of the loop and proceed to the connection
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(waitTime):
		}
	}
<<<<<<< HEAD:network/rateLimitedTransport.go
<<<<<<< HEAD:network/dialer.go
>>>>>>> Taking care of the lock triggering deadlock detection.
	conn, err := d.innerDialer.DialContext(ctx, network, address)
	d.phonebook.UpdateConnectionTime(address, provisionalTime)
=======
	conn, err := rlt.innerDialer.DialContext(ctx, network, address)
	rlt.phonebook.UpdateConnectionTime(address, provisionalTime)
>>>>>>> Adding RateLimitedTransport to wrap around the http.Transport:network/rateLimitedTransport.go
=======
	conn, err := d.innerDialer.DialContext(ctx, network, address)
	d.phonebook.UpdateConnectionTime(address, provisionalTime)
>>>>>>> Separating Dialer from Transport, initializing the Dialer and Transport params (timeout, etc):network/dialer.go

	return conn, err
>>>>>>> DRAFT: using channel to offload the mutex.
}
