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
	"errors"
	"net/http"
	"time"
)

// rateLimitingTransport is the transport for execute a single HTTP transaction, obtaining the Response for a given Request.
type rateLimitingTransport struct {
	phonebook       Phonebook
	innerTransport  *http.Transport
	queueingTimeout time.Duration
}

// ErrConnectionQueueingTimeout indicates that we've exceeded the time allocated for
// queueing the current request before the request attempt could be made.
var ErrConnectionQueueingTimeout = errors.New("rateLimitingTransport: queueing timeout")

// makeRateLimitingTransport creates a rate limiting http transport that would limit the requests rate
// according to the entries in the phonebook.
func makeRateLimitingTransport(phonebook Phonebook, queueingTimeout time.Duration, dialer *Dialer, maxIdleConnsPerHost int) rateLimitingTransport {
	defaultTransport := http.DefaultTransport.(*http.Transport)
	return rateLimitingTransport{
		phonebook: phonebook,
		innerTransport: &http.Transport{
			Proxy:                 defaultTransport.Proxy,
			DialContext:           dialer.innerDialContext,
			MaxIdleConns:          defaultTransport.MaxIdleConns,
			IdleConnTimeout:       defaultTransport.IdleConnTimeout,
			TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
			ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
			MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		},
		queueingTimeout: queueingTimeout,
	}
}

// RoundTrip connects to the address on the named network using the provided context.
// It waits if needed not to exceed connectionsRateLimitingCount.
func (r *rateLimitingTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	var waitTime time.Duration
	var provisionalTime time.Time
	queueingTimedOut := time.After(r.queueingTimeout)
	for {
		_, waitTime, provisionalTime = r.phonebook.GetConnectionWaitTime(req.Host)
		if waitTime == 0 {
			break // break out of the loop and proceed to the connection
		}
		select {
		case <-time.After(waitTime):
		case <-queueingTimedOut:
			return nil, ErrConnectionQueueingTimeout
		}
	}
	res, err = r.innerTransport.RoundTrip(req)
	r.phonebook.UpdateConnectionTime(req.Host, provisionalTime)
	return
}
