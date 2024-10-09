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
	GetConnectionWaitTime(addrOrPeerID string) (bool, time.Duration, time.Time)
	UpdateConnectionTime(addrOrPeerID string, provisionalTime time.Time) bool
}

// RateLimitingBoundTransport is the transport for execute a single HTTP transaction, obtaining the Response for a given Request.
type RateLimitingBoundTransport struct {
	phonebook       ConnectionTimeStore
	innerTransport  http.RoundTripper
	queueingTimeout time.Duration
	addrOrPeerID    string
}

// DefaultQueueingTimeout is the default timeout for queueing the request.
const DefaultQueueingTimeout = 10 * time.Second

// ErrConnectionQueueingTimeout indicates that we've exceeded the time allocated for
// queueing the current request before the request attempt could be made.
var ErrConnectionQueueingTimeout = errors.New("rateLimitingTransport: queueing timeout")

// MakeRateLimitingBoundTransport creates a rate limiting http transport that that:
// 1. would limit the requests rate according to the entries in the phonebook.
// 2. is bound to a specific target.
func MakeRateLimitingBoundTransport(phonebook ConnectionTimeStore, queueingTimeout time.Duration, dialer *Dialer, maxIdleConnsPerHost int, target string) RateLimitingBoundTransport {
	defaultTransport := http.DefaultTransport.(*http.Transport)
	innerTransport := &http.Transport{
		Proxy:                 defaultTransport.Proxy,
		DialContext:           dialer.innerDialContext,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		IdleConnTimeout:       defaultTransport.IdleConnTimeout,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
	}
	return MakeRateLimitingBoundTransportWithRoundTripper(phonebook, queueingTimeout, innerTransport, target)
}

// MakeRateLimitingBoundTransportWithRoundTripper creates a rate limiting http transport that:
// 1. would limit the requests rate according to the entries in the phonebook.
// 2. is bound to a specific target.
func MakeRateLimitingBoundTransportWithRoundTripper(phonebook ConnectionTimeStore, queueingTimeout time.Duration, rt http.RoundTripper, target string) RateLimitingBoundTransport {
	return RateLimitingBoundTransport{
		phonebook:       phonebook,
		innerTransport:  rt,
		queueingTimeout: queueingTimeout,
		addrOrPeerID:    target,
	}
}

// RoundTrip connects to the address on the named network using the provided context.
// It waits if needed not to exceed connectionsRateLimitingCount.
func (r *RateLimitingBoundTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	var waitTime time.Duration
	var provisionalTime time.Time
	if r.addrOrPeerID == "" {
		return nil, errors.New("rateLimitingTransport: target not set")
	}
	if req.URL != nil && req.URL.Host != "" && req.URL.Host != r.addrOrPeerID {
		return nil, errors.New("rateLimitingTransport: request URL host does not match the target")
	}

	queueingDeadline := time.Now().Add(r.queueingTimeout)
	for {
		_, waitTime, provisionalTime = r.phonebook.GetConnectionWaitTime(r.addrOrPeerID)
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
	r.phonebook.UpdateConnectionTime(r.addrOrPeerID, provisionalTime)
	return
}
