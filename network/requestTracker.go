// Copyright (C) 2019-2021 Algorand, Inc.
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
	connection         net.Conn
	noPrune            bool
}

// makeTrackerRequest creates a new TrackerRequest.
func makeTrackerRequest(remoteAddr, remoteHost, remotePort string, createTime time.Time, conn net.Conn) *TrackerRequest {
	if remoteHost == "" {
		remoteHost, remotePort, _ = net.SplitHostPort(remoteAddr)
	}

	return &TrackerRequest{
		created:    createTime,
		remoteAddr: remoteAddr,
		remoteHost: remoteHost,
		remotePort: remotePort,
		connection: conn,
	}
}

// hostIncomingRequests holds all the requests that are originating from a single host.
type hostIncomingRequests struct {
	remoteHost             string
	requests               []*TrackerRequest            // this is an ordered list, according to the requestsHistory.created
	additionalHostRequests map[*TrackerRequest]struct{} // additional requests that aren't included in the "requests", and always assumed to be "alive".
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

// convertToAdditionalRequest converts the given trackerRequest into a "additional request".
// unlike regular tracker requests, additional requests does not get pruned.
func (ard *hostIncomingRequests) convertToAdditionalRequest(trackerRequest *TrackerRequest) {
	if _, has := ard.additionalHostRequests[trackerRequest]; has {
		return
	}

	i := sort.Search(len(ard.requests), func(i int) bool {
		return ard.requests[i].created.After(trackerRequest.created)
	})
	i--
	if i < 0 {
		return
	}
	// we could have several entries with the same timestamp, so we need to consider all of them.
	for ; i >= 0; i-- {
		if ard.requests[i] == trackerRequest {
			break
		}
		if ard.requests[i].created != trackerRequest.created {
			// we can't find the item in the list.
			return
		}
	}
	if i < 0 {
		return
	}
	// ok, item was found at index i.
	copy(ard.requests[i:], ard.requests[i+1:])
	ard.requests[len(ard.requests)-1] = nil
	ard.requests = ard.requests[:len(ard.requests)-1]
	ard.additionalHostRequests[trackerRequest] = struct{}{}
}

// removeTrackedConnection removes a trackerRequest from the additional requests map
func (ard *hostIncomingRequests) removeTrackedConnection(trackerRequest *TrackerRequest) {
	delete(ard.additionalHostRequests, trackerRequest)
}

// add adds the trackerRequest at the correct index within the sorted array.
func (ard *hostIncomingRequests) add(trackerRequest *TrackerRequest) {
	// find the new item index.
	itemIdx := ard.findTimestampIndex(trackerRequest.created)
	if itemIdx >= len(ard.requests) {
		// it's going to be added as the last item on the list.
		ard.requests = append(ard.requests, trackerRequest)
		return
	}
	if itemIdx == 0 {
		// it's going to be added as the first item on the list.
		ard.requests = append([]*TrackerRequest{trackerRequest}, ard.requests...)
		return
	}
	// it's going to be added somewhere in the middle.
	ard.requests = append(ard.requests[:itemIdx], append([]*TrackerRequest{trackerRequest}, ard.requests[itemIdx:]...)...)
	return
}

// countConnections counts the number of connection that we have that occured after the provided specified time
func (ard *hostIncomingRequests) countConnections(rateLimitingWindowStartTime time.Time) (count uint) {
	i := ard.findTimestampIndex(rateLimitingWindowStartTime)
	return uint(len(ard.requests) - i + len(ard.additionalHostRequests))
}

type hostsIncomingMap map[string]*hostIncomingRequests

// pruneRequests cleans stale items from the hostRequests maps
func (him *hostsIncomingMap) pruneRequests(rateLimitingWindowStartTime time.Time) {
	// try to eliminate as many entries from a *single* connection. the goal here is not to wipe it clean
	// but rather to make a progressive cleanup.
	var removeHost string

	for host, requestData := range *him {
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
		delete(*him, removeHost)
	}
}

// addRequest adds an entry to the hostRequests map, or update the item within the map
func (him *hostsIncomingMap) addRequest(trackerRequest *TrackerRequest) {
	requestData, has := (*him)[trackerRequest.remoteHost]
	if !has {
		requestData = &hostIncomingRequests{
			remoteHost:             trackerRequest.remoteHost,
			requests:               make([]*TrackerRequest, 0, 1),
			additionalHostRequests: make(map[*TrackerRequest]struct{}),
		}
		(*him)[trackerRequest.remoteHost] = requestData
	}

	requestData.add(trackerRequest)
}

// countOriginConnections counts the number of connection that were seen since rateLimitingWindowStartTime coming from the host rateLimitingWindowStartTime
func (him *hostsIncomingMap) countOriginConnections(remoteHost string, rateLimitingWindowStartTime time.Time) uint {
	if requestData, has := (*him)[remoteHost]; has {
		return requestData.countConnections(rateLimitingWindowStartTime)
	}
	return 0
}

// convertToAdditionalRequest converts the given trackerRequest into a "additional request".
func (him *hostsIncomingMap) convertToAdditionalRequest(trackerRequest *TrackerRequest) {
	requestData, has := (*him)[trackerRequest.remoteHost]
	if !has {
		return
	}
	requestData.convertToAdditionalRequest(trackerRequest)
}

// removeTrackedConnection removes a trackerRequest from the additional requests map
func (him *hostsIncomingMap) removeTrackedConnection(trackerRequest *TrackerRequest) {
	requestData, has := (*him)[trackerRequest.remoteHost]
	if !has {
		return
	}
	requestData.removeTrackedConnection(trackerRequest)
}

// RequestTracker tracks the incoming request connections
type RequestTracker struct {
	downstreamHandler http.Handler
	log               logging.Logger
	config            config.Local
	// once we detect that we have a misconfigured UseForwardedForAddress, we set this and write an warning message.
	misconfiguredUseForwardedForAddress bool

	listener net.Listener // this is the downsteam listener

	hostRequests        hostsIncomingMap             // maps a request host to a request data (i.e. "1.2.3.4" -> *hostIncomingRequests )
	acceptedConnections map[net.Addr]*TrackerRequest // maps a local address interface  to a tracked request data (i.e. "1.2.3.4:1560" -> *TrackerRequest ); used to associate connection between the Accept and the ServeHTTP
	hostRequestsMu      deadlock.Mutex               // used to syncronize access to the hostRequests and acceptedConnections variables

	httpHostRequests  hostsIncomingMap             // maps a request host to a request data (i.e. "1.2.3.4" -> *hostIncomingRequests )
	httpConnections   map[net.Addr]*TrackerRequest // maps a local address interface  to a tracked request data (i.e. "1.2.3.4:1560" -> *TrackerRequest ); used to associate connection between the Accept and the ServeHTTP
	httpConnectionsMu deadlock.Mutex               // used to syncronize access to the httpHostRequests and httpConnections variables
}

// makeRequestsTracker creates a request tracker object.
func makeRequestsTracker(downstreamHandler http.Handler, log logging.Logger, config config.Local) *RequestTracker {
	return &RequestTracker{
		downstreamHandler:   downstreamHandler,
		log:                 log,
		config:              config,
		hostRequests:        make(map[string]*hostIncomingRequests, 0),
		acceptedConnections: make(map[net.Addr]*TrackerRequest, 0),
		httpConnections:     make(map[net.Addr]*TrackerRequest, 0),
		httpHostRequests:    make(map[string]*hostIncomingRequests, 0),
	}
}

// requestTrackedConnection used to track the active connections. In particular, it used to remove the
// tracked connection entry from the RequestTracker once a connection is closed.
type requestTrackedConnection struct {
	net.Conn
	tracker *RequestTracker
}

// Close removes the connection from the tracker's connections map and call the underlaying Close function.
func (c *requestTrackedConnection) Close() error {
	c.tracker.hostRequestsMu.Lock()
	trackerRequest := c.tracker.acceptedConnections[c.Conn.LocalAddr()]
	delete(c.tracker.acceptedConnections, c.Conn.LocalAddr())
	if trackerRequest != nil {
		c.tracker.hostRequests.removeTrackedConnection(trackerRequest)
	}
	c.tracker.hostRequestsMu.Unlock()
	return c.Conn.Close()
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

		trackerRequest := makeTrackerRequest(conn.RemoteAddr().String(), "", "", time.Now(), conn)
		rateLimitingWindowStartTime := trackerRequest.created.Add(-time.Duration(rt.config.ConnectionsRateLimitingWindowSeconds) * time.Second)

		rt.hostRequestsMu.Lock()
		rt.hostRequests.addRequest(trackerRequest)
		rt.hostRequests.pruneRequests(rateLimitingWindowStartTime)
		originConnections := rt.hostRequests.countOriginConnections(trackerRequest.remoteHost, rateLimitingWindowStartTime)

		rateLimitedRemoteHost := (!rt.config.DisableLocalhostConnectionRateLimit) || (!isLocalhost(trackerRequest.remoteHost))
		connectionLimitEnabled := rt.config.ConnectionsRateLimitingWindowSeconds > 0 && rt.config.ConnectionsRateLimitingCount > 0

		// check the number of connections
		if originConnections > rt.config.ConnectionsRateLimitingCount && connectionLimitEnabled && rateLimitedRemoteHost {
			rt.hostRequestsMu.Unlock()
			networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "incoming_connection_per_ip_tcp_rate_limit"})
			rt.log.With("connection", "tcp").With("count", originConnections).Debugf("Rejected connection due to excessive connections attempt rate")
			rt.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerFailEvent,
				telemetryspec.ConnectPeerFailEventDetails{
					Address:  trackerRequest.remoteHost,
					Incoming: true,
					Reason:   "Remote IP Connection TCP Rate Limit",
				})

			// we've already *doubled* the amount of allowed connections; disconnect right away.
			// we don't want to create more go routines beyond this point.
			if originConnections > rt.config.ConnectionsRateLimitingCount*2 {
				err := conn.Close()
				if err != nil {
					rt.log.With("connection", "tcp").With("count", originConnections).Debugf("Failed to close connection : %v", err)
				}
			} else {
				// we want to make an attempt to read the connection reqest and send a response, but not within this go routine -
				// this go routine is used single-threaded and should not get blocked.
				go rt.sendBlockedConnectionResponse(conn, trackerRequest.created)
			}
			continue
		}

		rt.pruneAcceptedConnections(trackerRequest.created.Add(-maxHeaderReadTimeout))
		// add an entry to the acceptedConnections so that the ServeHTTP could find the connection quickly.
		rt.acceptedConnections[conn.LocalAddr()] = trackerRequest
		rt.hostRequestsMu.Unlock()
		conn = &requestTrackedConnection{Conn: conn, tracker: rt}
		return
	}
}

// sendBlockedConnectionResponse reads the incoming connection request followed by sending a "too many requests" response.
func (rt *RequestTracker) sendBlockedConnectionResponse(conn net.Conn, requestTime time.Time) {
	defer func() {
		err := conn.Close()
		if err != nil {
			rt.log.With("connection", "tcp").Debugf("Failed to close connection of blocked connection response: %v", err)
		}
	}()
	err := conn.SetReadDeadline(requestTime.Add(500 * time.Millisecond))
	if err != nil {
		rt.log.With("connection", "tcp").Debugf("Failed to set a read deadline of blocked connection response: %v", err)
		return
	}
	err = conn.SetWriteDeadline(requestTime.Add(500 * time.Millisecond))
	if err != nil {
		rt.log.With("connection", "tcp").Debugf("Failed to set a write deadline of blocked connection response: %v", err)
		return
	}
	var dummyBuffer [1024]byte
	var readingErr error
	for readingErr == nil {
		_, readingErr = conn.Read(dummyBuffer[:])
	}
	// this is not a normal - usually we want to wait for the HTTP handler to give the response; however, it seems that we're either getting requests faster than the
	// http handler can handle, or getting requests that fails before the header retrieval is complete.
	// in this case, we want to send our response right away and disconnect. If the client is currently still sending it's request, it might not know how to handle
	// this correctly. This use case is similar to the issue handled by the go-server in the same manner. ( see "431 Request Header Fields Too Large" in the server.go )
	_, err = conn.Write([]byte(
		fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n%s: %d\r\n\r\n", http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests), TooManyRequestsRetryAfterHeader, rt.config.ConnectionsRateLimitingWindowSeconds)))
	if err != nil {
		rt.log.With("connection", "tcp").Debugf("Failed to write response to a blocked connection response: %v", err)
		return
	}
}

// pruneAcceptedConnections clean stale items form the acceptedConnections map; it's syncornized via the acceptedConnectionsMu mutex which is expected to be taken by the caller.
// in case the created is 0, the pruning is disabled for this connection. The HTTP handlers would call Close to have this entry cleared out.
func (rt *RequestTracker) pruneAcceptedConnections(pruneStartDate time.Time) {
	localAddrToRemove := []net.Addr{}
	for localAddr, request := range rt.acceptedConnections {
		if request.noPrune == false && request.created.Before(pruneStartDate) {
			localAddrToRemove = append(localAddrToRemove, localAddr)
		}
	}
	for _, localAddr := range localAddrToRemove {
		delete(rt.acceptedConnections, localAddr)
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (rt *RequestTracker) Close() error {
	return rt.listener.Close()
}

func (rt *RequestTracker) getWaitUntilEmptyChannel(checkInterval time.Duration) <-chan struct{}{
	done := make(chan struct{})

	go func() {
		checkEmpty := func (rt *RequestTracker) bool {
			rt.httpConnectionsMu.Lock()
			defer rt.httpConnectionsMu.Unlock()
			return len(rt.httpConnections) == 0
		}

		for true {
			if checkEmpty(rt) {
				close(done)
				return
			}

			time.Sleep(checkInterval)
		}
	}()

	return done
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
	rt.httpConnectionsMu.Lock()
	defer rt.httpConnectionsMu.Unlock()
	localAddr := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return rt.httpConnections[localAddr]
}

// GetRequestConnection return the underlying connection for the given request
func (rt *RequestTracker) GetRequestConnection(request *http.Request) net.Conn {
	rt.httpConnectionsMu.Lock()
	defer rt.httpConnectionsMu.Unlock()
	localAddr := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return rt.httpConnections[localAddr].connection
}

func (rt *RequestTracker) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// this function is called only after we've fetched all the headers. on some malicious clients, this could get delayed, so we can't rely on the
	// tcp-connection established time to align with current time.
	rateLimitingWindowStartTime := time.Now().Add(-time.Duration(rt.config.ConnectionsRateLimitingWindowSeconds) * time.Second)

	// get the connection local address. Note that it's the interface of a immutable object, so it will be unique and matching the original connection interface.
	localAddr := request.Context().Value(http.LocalAddrContextKey).(net.Addr)

	rt.hostRequestsMu.Lock()
	trackedRequest := rt.acceptedConnections[localAddr]
	if trackedRequest != nil {
		// update the original tracker request so that it won't get pruned.
		if trackedRequest.noPrune == false {
			trackedRequest.noPrune = true
			rt.hostRequests.convertToAdditionalRequest(trackedRequest)
		}
		// create a copy, so we can unlock
		trackedRequest = makeTrackerRequest(trackedRequest.remoteAddr, trackedRequest.remoteHost, trackedRequest.remotePort, trackedRequest.created, trackedRequest.connection)
	}
	rt.hostRequestsMu.Unlock()

	// we have no request tracker ? no problem; create one on the fly.
	if trackedRequest == nil {
		trackedRequest = makeTrackerRequest(request.RemoteAddr, "", "", time.Now(), nil)
	}

	// update the origin address.
	rt.updateRequestRemoteAddr(trackedRequest, request)

	rt.httpConnectionsMu.Lock()
	trackedRequest.request = request
	trackedRequest.otherTelemetryGUID, trackedRequest.otherInstanceName, trackedRequest.otherPublicAddr = getCommonHeaders(request.Header)
	rt.httpHostRequests.addRequest(trackedRequest)
	rt.httpHostRequests.pruneRequests(rateLimitingWindowStartTime)
	originConnections := rt.httpHostRequests.countOriginConnections(trackedRequest.remoteHost, rateLimitingWindowStartTime)
	rt.httpConnections[localAddr] = trackedRequest
	rt.httpConnectionsMu.Unlock()

	defer func() {
		rt.httpConnectionsMu.Lock()
		defer rt.httpConnectionsMu.Unlock()
		// now that we're done with it, we can remove the trackedRequest from the httpConnections.
		delete(rt.httpConnections, localAddr)
	}()

	rateLimitedRemoteHost := (!rt.config.DisableLocalhostConnectionRateLimit) || (!isLocalhost(trackedRequest.remoteHost))
	connectionLimitEnabled := rt.config.ConnectionsRateLimitingWindowSeconds > 0 && rt.config.ConnectionsRateLimitingCount > 0

	if originConnections > rt.config.ConnectionsRateLimitingCount && connectionLimitEnabled && rateLimitedRemoteHost {
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

// updateRequestRemoteAddr updates the origin IP address in both the trackedRequest as well as in the request.RemoteAddr string
func (rt *RequestTracker) updateRequestRemoteAddr(trackedRequest *TrackerRequest, request *http.Request) {
	originIP := rt.getForwardedConnectionAddress(request.Header)
	if originIP == nil {
		return
	}
	request.RemoteAddr = originIP.String() + ":" + trackedRequest.remotePort
	trackedRequest.remoteHost = originIP.String()
}

// retrieve the origin ip address from the http header, if such exists and it's a valid ip address.
func (rt *RequestTracker) getForwardedConnectionAddress(header http.Header) (ip net.IP) {
	if rt.config.UseXForwardedForAddressField == "" {
		return
	}
	forwardedForString := header.Get(rt.config.UseXForwardedForAddressField)
	if forwardedForString == "" {
		rt.httpConnectionsMu.Lock()
		defer rt.httpConnectionsMu.Unlock()
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

// isLocalhost returns true if the given host is a localhost address.
func isLocalhost(host string) bool {
	for _, v := range []string{"localhost", "127.0.0.1", "[::1]", "::1", "[::]"} {
		if host == v {
			return true
		}
	}
	return false
}
