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

package network

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

const (
	// maxHeaderReadTimeout is the time limit where items would remain in the acceptedConnections cache before being pruned.
	// certain malicious connections would never get to the http handler, and therefore must be pruned every so often.
	maxHeaderReadTimeout = 30 * time.Second
)

// TrackerRequest hold the tracking data associated with a single request.
type TrackerRequest struct {
	created            time.Time
	remoteHost         string
	remotePort         string
	remoteAddr         string
	request            *http.Request
	otherTelemetryGUID string
	otherInstanceName  string
	otherPublicAddr    string
}

// hostIncomingRequests holds all the requests that are originating from a single host.
type hostIncomingRequests struct {
	remoteHost string
	requests   []*TrackerRequest // this is an ordered list, according to the requestsHistory.created
}

// findTimestampIndex finds the first an index (i) in the sorted requests array, where requests[i].created is greater than t.
// if no such item exists, it returns the index where the item should
func (ard *hostIncomingRequests) findTimestampIndex(t time.Time) int {
	if len(ard.requests) == 0 {
		return 0
	}
	i := sort.Search(len(ard.requests), func(i int) bool {
		return ard.requests[i].created.After(t)
	})
	return i
}

func (ard *hostIncomingRequests) add(remoteHost, remotePort, remoteAddr string, createTime time.Time, rateLimitingWindowStartTime time.Time) (newEntry *TrackerRequest) {
	// keep track of the recent connection attempts ( up to ConnectionsRateLimitingWindowSeconds second into the past )
	newEntry = &TrackerRequest{
		created:    createTime,
		remoteHost: remoteHost,
		remotePort: remotePort,
		remoteAddr: remoteAddr,
	}
	// prune list first.
	pruneIdx := ard.findTimestampIndex(rateLimitingWindowStartTime)
	if pruneIdx > 0 {
		ard.requests = ard.requests[pruneIdx:]
	}
	// find the new item index.
	itemIdx := ard.findTimestampIndex(newEntry.created)
	if itemIdx >= len(ard.requests) {
		// it's going to be added as the last item on the list.
		ard.requests = append(ard.requests, newEntry)
		return
	}
	if itemIdx == 0 {
		// it's going to be added as the first item on the list.
		ard.requests = append([]*TrackerRequest{newEntry}, ard.requests...)
		return
	}
	// it's going to be added somewhere in the middle.
	ard.requests = append(ard.requests[:itemIdx], append([]*TrackerRequest{newEntry}, ard.requests[itemIdx:]...)...)
	return
}

func (ard *hostIncomingRequests) remove(trackedRequest *TrackerRequest) {
	for i := range ard.requests {
		if ard.requests[i] == trackedRequest {
			// remove entry.
			ard.requests = append(ard.requests[0:i], ard.requests[i+1:]...)
			return
		}
	}
}

func (ard *hostIncomingRequests) countConnections(rateLimitingWindowStartTime time.Time, tcpRequests bool) (count uint) {
	i := ard.findTimestampIndex(rateLimitingWindowStartTime)
	if tcpRequests {
		for ; i < len(ard.requests); i++ {
			if ard.requests[i].request == nil {
				count++
			}
		}
	} else {
		for ; i < len(ard.requests); i++ {
			if ard.requests[i].request != nil {
				count++
			}
		}
	}
	return
}

// RequestTracker tracks the incoming request connections
type RequestTracker struct {
	downstreamHandler http.Handler
	log               logging.Logger
	config            config.Local
	// once we detect that we have a misconfigured UseForwardedForAddress, we set this and write an warning message.
	misconfiguredUseForwardedForAddress bool

	listener              net.Listener
	hostRequests          map[string]*hostIncomingRequests // maps a request host to a request data (i.e. "1.2.3.4" -> *hostIncomingRequests )
	hostRequestsMu        deadlock.Mutex
	acceptedConnections   map[net.Addr]*TrackerRequest // maps a local address interface  to a tracked request data (i.e. "1.2.3.4:1560" -> *TrackerRequest ); used to associate connection between the Accept and the ServeHTTP
	acceptedConnectionsMu deadlock.Mutex
}

func makeRequestsTracker(downstreamHandler http.Handler, log logging.Logger, config config.Local) *RequestTracker {
	return &RequestTracker{
		downstreamHandler:   downstreamHandler,
		log:                 log,
		config:              config,
		hostRequests:        make(map[string]*hostIncomingRequests, 0),
		acceptedConnections: make(map[net.Addr]*TrackerRequest, 0),
	}
}

// Accept waits for and returns the next connection to the listener.
func (rt *RequestTracker) Accept() (conn net.Conn, err error) {
	// the following for loop is a bit tricky :
	// in the normal use case, we accept the connection and exit right away.
	// the only case where the for loop is being iterated is when we are rejecting a connection.
	for {
		conn, err = rt.listener.Accept()
		if err != nil || conn == nil {
			return
		}
		requestTime := time.Now()
		remoteAddr := conn.RemoteAddr().String()
		var remoteHost, remotePort string
		remoteHost, remotePort, err = net.SplitHostPort(remoteAddr)
		if err != nil {
			// this error should not happen. The go framework is responsible for returning a valid remote address.
			conn = nil
			return
		}
		rateLimitingWindowStartTime := requestTime.Add(-time.Duration(rt.config.ConnectionsRateLimitingWindowSeconds) * time.Second)

		rt.hostRequestsMu.Lock()
		trackerRequest := rt.addRequest(remoteHost, remotePort, remoteAddr, requestTime, rateLimitingWindowStartTime)
		rt.pruneRequests(rateLimitingWindowStartTime)
		originConnections := rt.countOriginConnections(remoteHost, rateLimitingWindowStartTime, true)
		rt.hostRequestsMu.Unlock()

		// check the number of connections
		if originConnections > rt.config.ConnectionsRateLimitingCount && rt.config.ConnectionsRateLimitingWindowSeconds > 0 && rt.config.ConnectionsRateLimitingCount > 0 {
			networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "incoming_connection_per_ip_tcp_rate_limit"})
			rt.log.With("connection", "tcp").With("count", originConnections).Debugf("Rejected connection due to excessive connections attempt rate")
			rt.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerFailEvent,
				telemetryspec.ConnectPeerFailEventDetails{
					Address:  remoteHost,
					Incoming: true,
					Reason:   "Remote IP Connection TCP Rate Limit",
				})

			// we've already *doubled* the amount of allowed connections; disconnect right away.
			// we don't want to create more go routines beyond this point.
			if originConnections > rt.config.ConnectionsRateLimitingCount*2 {
				conn.Close()
			} else {
				// we want to make an attempt to read the connection reqest and send a response, but not within this go routine -
				// this go routine is used single-threaded and should not get blocked.
				go rt.sendBlockedConnectionResponse(conn, requestTime)
			}
			continue
		}

		rt.acceptedConnectionsMu.Lock()
		defer rt.acceptedConnectionsMu.Unlock()

		rt.pruneAcceptedConnections(requestTime.Add(-maxHeaderReadTimeout))
		// add an entry to the acceptedConnections so that the ServeHTTP could find the connection quickly.
		rt.acceptedConnections[conn.LocalAddr()] = trackerRequest
		return
	}
}

// sendBlockedConnectionResponse reads the incoming connection request followed by sending a "too many requests" response.
func (rt *RequestTracker) sendBlockedConnectionResponse(conn net.Conn, requestTime time.Time) {
	conn.SetReadDeadline(requestTime.Add(500 * time.Millisecond))
	conn.SetWriteDeadline(requestTime.Add(500 * time.Millisecond))
	var dummyBuffer [512]byte
	conn.Read(dummyBuffer[:])
	// this is not a normal - usually we want to wait for the HTTP handler to give the response; however, it seems that we're either getting requests faster than the
	// http handler can handle, or getting requests that fails before the header retrieval is complete.
	// in this case, we want to send our response right away and disconnect. If the client is currently still sending it's request, it might not know how to handle
	// this correctly. This use case is similar to the issue handled by the go-server in the same manner. ( see "431 Request Header Fields Too Large" in the server.go )
	conn.Write([]byte(
		fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n%s: %d\r\n\r\n", http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests), TooManyRequestsRetryAfterHeader, rt.config.ConnectionsRateLimitingWindowSeconds)))
	conn.Close()
}

// pruneAcceptedConnections clean stale items form the acceptedConnections map; it's syncornized via the acceptedConnectionsMu mutex which is expected to be taken by the caller.
func (rt *RequestTracker) pruneAcceptedConnections(pruneStartDate time.Time) {
	localAddrToRemove := []net.Addr{}
	for localAddr, request := range rt.acceptedConnections {
		if request.request == nil && request.created.Before(pruneStartDate) {
			localAddrToRemove = append(localAddrToRemove, localAddr)
		}
	}
	for _, localAddr := range localAddrToRemove {
		delete(rt.acceptedConnections, localAddr)
	}
}

// pruneRequests cleans stale items from the hostRequests maps; it's syncornized via the hostRequestsMu mutex which is expected to be taken by the caller.
func (rt *RequestTracker) pruneRequests(rateLimitingWindowStartTime time.Time) {
	// try to eliminate as many entries from a *single* connection. the goal here is not to wipe it clean
	// but rather to make a progressive cleanup.
	var removeHost string
	for host, requestData := range rt.hostRequests {
		i := requestData.findTimestampIndex(rateLimitingWindowStartTime)
		if i == 0 {
			continue
		}

		requestData.requests = requestData.requests[i:]
		if len(requestData.requests) == 0 {
			// remove the entire key.
			removeHost = host
		}
		break
	}
	if removeHost != "" {
		delete(rt.hostRequests, removeHost)
	}
}

// addRequest adds an entry to the hostRequests map, or update the item within the map; it's syncornized via the hostRequestsMu mutex which is expected to be taken by the caller.
func (rt *RequestTracker) addRequest(host, port, remoteAddr string, requestTime time.Time, rateLimitingWindowStartTime time.Time) *TrackerRequest {
	requestData, has := rt.hostRequests[host]
	if !has {
		requestData = &hostIncomingRequests{
			remoteHost: host,
			requests:   make([]*TrackerRequest, 0, 1),
		}
		rt.hostRequests[host] = requestData
	}
	return requestData.add(host, port, remoteAddr, requestTime, rateLimitingWindowStartTime)
}

// removeRequest removes an entry of the hostRequests map, or update the item within the map; it's syncornized via the hostRequestsMu mutex which is expected to be taken by the caller.
func (rt *RequestTracker) removeRequest(trackedRequest *TrackerRequest) {
	hostRequests := rt.hostRequests[trackedRequest.remoteHost]
	if hostRequests != nil {
		hostRequests.remove(trackedRequest)
		if len(hostRequests.requests) == 0 {
			delete(rt.hostRequests, trackedRequest.remoteHost)
		}
	}
}

// countOriginConnections counts the number of connection that were seen since rateLimitingWindowStartTime coming from the host rateLimitingWindowStartTime; it's syncornized via the hostRequestsMu mutex which is expected to be taken by the caller.
func (rt *RequestTracker) countOriginConnections(remoteHost string, rateLimitingWindowStartTime time.Time, tcpRequests bool) uint {
	if requestData, has := rt.hostRequests[remoteHost]; has {
		return requestData.countConnections(rateLimitingWindowStartTime, tcpRequests)
	}
	return 0
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (rt *RequestTracker) Close() error {
	return rt.listener.Close()
}

// Addr returns the listener's network address.
func (rt *RequestTracker) Addr() net.Addr {
	return rt.listener.Addr()
}

// Listener initialize the underlaying listener, and return the request tracker wrapping listener
func (rt *RequestTracker) Listener(listener net.Listener) net.Listener {
	rt.listener = listener
	return rt
}

// GetTrackedRequest return the tracked request
func (rt *RequestTracker) GetTrackedRequest(request *http.Request) (trackedRequest *TrackerRequest) {
	rt.acceptedConnectionsMu.Lock()
	defer rt.acceptedConnectionsMu.Unlock()
	localAddr := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return rt.acceptedConnections[localAddr]
}

func (rt *RequestTracker) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// this function is called only after we've fetched all the headers. on some malicious clients, this could get delayed, so we can't rely on the
	// tcp-connection established time to align with current time.
	rateLimitingWindowStartTime := time.Now().Add(-time.Duration(rt.config.ConnectionsRateLimitingWindowSeconds) * time.Second)

	trackedRequest, localAddr := rt.updateRequestRemoteAddr(request, rateLimitingWindowStartTime)
	if trackedRequest == nil {
		rt.log.Errorf("missing entry for %s in acceptedConnection map", request.RemoteAddr)
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	defer func() {
		rt.acceptedConnectionsMu.Lock()
		defer rt.acceptedConnectionsMu.Unlock()
		// now that we're done with it, we can remove the trackedRequest from the acceptedConnections.
		delete(rt.acceptedConnections, localAddr)
	}()

	rt.hostRequestsMu.Lock()
	trackedRequest.request = request
	trackedRequest.otherTelemetryGUID, trackedRequest.otherInstanceName, trackedRequest.otherPublicAddr = getCommonHeaders(request.Header)
	originConnections := rt.countOriginConnections(trackedRequest.remoteHost, rateLimitingWindowStartTime, false)
	rt.hostRequestsMu.Unlock()

	if originConnections > rt.config.ConnectionsRateLimitingCount && rt.config.ConnectionsRateLimitingWindowSeconds > 0 && rt.config.ConnectionsRateLimitingCount > 0 {
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "incoming_connection_per_ip_rate_limit"})
		rt.log.With("connection", "http").With("count", originConnections).Debugf("Rejected connection due to excessive connections attempt rate")
		rt.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerFailEvent,
			telemetryspec.ConnectPeerFailEventDetails{
				Address:      trackedRequest.remoteHost,
				HostName:     trackedRequest.otherTelemetryGUID,
				Incoming:     true,
				InstanceName: trackedRequest.otherInstanceName,
				Reason:       "Remote IP Connection Rate Limit",
			})
		response.Header().Add(TooManyRequestsRetryAfterHeader, fmt.Sprintf("%d", rt.config.ConnectionsRateLimitingWindowSeconds))
		response.WriteHeader(http.StatusTooManyRequests)
		return
	}

	// send the request downstream; in our case, it would go to the router.
	rt.downstreamHandler.ServeHTTP(response, request)

}

func (rt *RequestTracker) updateRequestRemoteAddr(request *http.Request, rateLimitingWindowStartTime time.Time) (trackedRequest *TrackerRequest, localAddr net.Addr) {
	localAddr = request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	rt.acceptedConnectionsMu.Lock()
	trackedRequest = rt.acceptedConnections[localAddr]
	rt.acceptedConnectionsMu.Unlock()

	originIP := rt.getForwardedConnectionAddress(request.Header)
	if originIP == nil && trackedRequest != nil {
		return
	}

	if trackedRequest != nil {
		request.RemoteAddr = originIP.String() + ":" + trackedRequest.remotePort
		rt.hostRequestsMu.Lock()
		trackedRequest.remoteHost = originIP.String()
		rt.hostRequestsMu.Unlock()
	} else {
		// we don't have the request, so create a new one.
		remoteHost, remotePort, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			// this error should not happen. The go framework is responsible for returning a valid remote address.
			return
		}

		rt.hostRequestsMu.Lock()
		trackedRequest = rt.addRequest(remoteHost, remotePort, request.RemoteAddr, time.Now(), rateLimitingWindowStartTime)
		rt.hostRequestsMu.Unlock()

		rt.acceptedConnectionsMu.Lock()
		defer rt.acceptedConnectionsMu.Unlock()
		rt.acceptedConnections[localAddr] = trackedRequest
	}
	return
}

// retrieve the origin ip address from the http header, if such exists and it's a valid ip address.
func (rt *RequestTracker) getForwardedConnectionAddress(header http.Header) (ip net.IP) {
	if rt.config.UseXForwardedForAddressField == "" {
		return
	}
	forwardedForString := header.Get(rt.config.UseXForwardedForAddressField)
	if forwardedForString == "" {
		if !rt.misconfiguredUseForwardedForAddress {
			rt.log.Warnf("UseForwardedForAddressField is configured as '%s', but no value was retrieved from header", rt.config.UseXForwardedForAddressField)
			rt.misconfiguredUseForwardedForAddress = true
		}
		return
	}
	ip = net.ParseIP(forwardedForString)
	if ip == nil {
		// if origin isn't a valid IP Address, log this.,
		rt.log.Warnf("unable to parse origin address: '%s'", forwardedForString)
	}
	return
}
