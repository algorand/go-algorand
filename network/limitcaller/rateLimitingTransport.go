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

package limitcaller

import (
	"errors"
	"net/http"
	"time"

	"github.com/algorand/go-algorand/util"
)

// ConnectionTimeStore is a subset of the phonebook that is used to store the connection times.
type ConnectionTimeStore interface {
	GetConnectionWaitTime(addrOrInfo interface{}) (bool, time.Duration, time.Time)
	UpdateConnectionTime(addrOrInfo interface{}, provisionalTime time.Time) bool
}

// RateLimitingTransport is the transport for execute a single HTTP transaction, obtaining the Response for a given Request.
type RateLimitingTransport struct {
	phonebook       ConnectionTimeStore
	innerTransport  http.RoundTripper
	queueingTimeout time.Duration
	targetAddr      interface{} // target address for the p2p http request
}

// DefaultQueueingTimeout is the default timeout for queueing the request.
const DefaultQueueingTimeout = 10 * time.Second

// ErrConnectionQueueingTimeout indicates that we've exceeded the time allocated for
// queueing the current request before the request attempt could be made.
var ErrConnectionQueueingTimeout = errors.New("rateLimitingTransport: queueing timeout")

// MakeRateLimitingTransport creates a rate limiting http transport that would limit the requests rate
// according to the entries in the phonebook.
func MakeRateLimitingTransport(phonebook ConnectionTimeStore, queueingTimeout time.Duration, dialer *Dialer, maxIdleConnsPerHost int) RateLimitingTransport {
	defaultTransport := http.DefaultTransport.(*http.Transport)
	return RateLimitingTransport{
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

// MakeRateLimitingTransportWithRoundTripper creates a rate limiting http transport that would limit the requests rate
// according to the entries in the phonebook.
func MakeRateLimitingTransportWithRoundTripper(phonebook ConnectionTimeStore, queueingTimeout time.Duration, rt http.RoundTripper, target interface{}, maxIdleConnsPerHost int) RateLimitingTransport {
	return RateLimitingTransport{
		phonebook:       phonebook,
		innerTransport:  rt,
		queueingTimeout: queueingTimeout,
		targetAddr:      target,
	}
}

// RoundTrip connects to the address on the named network using the provided context.
// It waits if needed not to exceed connectionsRateLimitingCount.
func (r *RateLimitingTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	var waitTime time.Duration
	var provisionalTime time.Time
	queueingDeadline := time.Now().Add(r.queueingTimeout)
	var host interface{} = req.Host
	// p2p/http clients have per-connection transport and address info so use that
	if len(req.Host) == 0 && req.URL != nil && len(req.URL.Host) == 0 {
		host = r.targetAddr
	}
	for {
		_, waitTime, provisionalTime = r.phonebook.GetConnectionWaitTime(host)
		if waitTime == 0 {
			break // break out of the loop and proceed to the connection
		}
		waitDeadline := time.Now().Add(waitTime)
		if waitDeadline.Before(queueingDeadline) {
			util.NanoSleep(waitTime)
			continue
		}
		return nil, ErrConnectionQueueingTimeout
	}
	res, err = r.innerTransport.RoundTrip(req)
	r.phonebook.UpdateConnectionTime(host, provisionalTime)
	return
}
