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

func (ard *hostIncomingRequests) countConnections(rateLimitingWindowStartTime time.Time, tcpRequestsOnly bool) (count uint) {
	i := ard.findTimestampIndex(rateLimitingWindowStartTime)
	if !tcpRequestsOnly {
		count = uint(len(ard.requests) - i)
		return
	}
	for ; i < len(ard.requests); i++ {
		if ard.requests[i].request != nil {
			count++
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
	remoteHostRequests    map[string]*hostIncomingRequests // maps request host to request data (i.e. "1.2.3.4" -> *hostIncomingRequests )
	remoteHostRequestsMu  deadlock.Mutex
	acceptedConnections   map[string]*TrackerRequest // maps a remote address to a tracked request data (i.e. "1.2.3.4:1560" -> *TrackerRequest ); used to associate connection between the Accept and the ServeHTTP
	acceptedConnectionsMu deadlock.Mutex
}

func makeRequestsTracker(downstreamHandler http.Handler, log logging.Logger, config config.Local) *RequestTracker {
	return &RequestTracker{
		downstreamHandler:   downstreamHandler,
		log:                 log,
		config:              config,
		remoteHostRequests:  make(map[string]*hostIncomingRequests, 0),
		acceptedConnections: make(map[string]*TrackerRequest, 0),
	}
}

// Accept waits for and returns the next connection to the listener.
func (rt *RequestTracker) Accept() (conn net.Conn, err error) {
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

		rt.remoteHostRequestsMu.Lock()
		trackerRequest := rt.addAcceptedConnection(remoteHost, remotePort, remoteAddr, requestTime, rateLimitingWindowStartTime)
		rt.pruneRequests(rateLimitingWindowStartTime)
		originConnections := rt.countOriginConnections(remoteHost, rateLimitingWindowStartTime, true)
		rt.remoteHostRequestsMu.Unlock()

		// check the number of connections
		if originConnections > rt.config.ConnectionsRateLimitingCount && rt.config.ConnectionsRateLimitingWindowSeconds > 0 && rt.config.ConnectionsRateLimitingCount > 0 {
			networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "incoming_connection_per_ip_tcp_rate_limit"})

			rt.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerFailEvent,
				telemetryspec.ConnectPeerFailEventDetails{
					Address:  remoteHost,
					Incoming: true,
					Reason:   "Remote IP Connection TCP Rate Limit",
				})

			// this is not a normal - usually we want to wait for the HTTP handler to give the response; however, it seems that we're either getting requests faster than the
			// http handler can handle, or getting requests that fails before the header retrieval is complete.
			// in this case, we want to send our response right away and disconnect. If the client is currently still sending it's request, it might not know how to handle
			// this correctly. This use case is similar to the issue handled by the go-server in the same manner. ( see "431 Request Header Fields Too Large" in the server.go )
			conn.Write([]byte(
				fmt.Sprintf("HTTP/1.1 %d Too Many Requests\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n%s: %d\r\n\r\n", http.StatusTooManyRequests, TooManyRequestsRetryAfterHeader, rt.config.ConnectionsRateLimitingWindowSeconds)))
			conn.Close()
			continue
		}

		rt.acceptedConnectionsMu.Lock()
		defer rt.acceptedConnectionsMu.Unlock()
		rt.pruneAcceptedConnections(rateLimitingWindowStartTime)
		// add an entry to the acceptedConnections so that the ServeHTTP could find the connection quickly.
		rt.acceptedConnections[remoteAddr] = trackerRequest
		return
	}

}

func (rt *RequestTracker) pruneAcceptedConnections(rateLimitingWindowStartTime time.Time) {
	requestsToRemove := []*TrackerRequest{}
	for _, request := range rt.acceptedConnections {
		if request.created.Before(rateLimitingWindowStartTime) {
			requestsToRemove = append(requestsToRemove, request)
		}
	}
	for _, request := range requestsToRemove {
		delete(rt.acceptedConnections, request.remoteAddr)
	}
}

func (rt *RequestTracker) pruneRequests(rateLimitingWindowStartTime time.Time) {
	// try to eliminate as many entries from a *single* connection. the goal here is not to wipe it clean
	// but rather to make a progressive cleanup.
	for host, requestData := range rt.remoteHostRequests {
		i := -1
		for j, reqData := range requestData.requests {
			if reqData.created.After(rateLimitingWindowStartTime) {
				break
			}
			i = j
		}
		if i == -1 {
			continue
		}

		requestData.requests = requestData.requests[i+1:]
		if len(requestData.requests) == 0 {
			// remove the entire key.
			delete(rt.remoteHostRequests, host)
		}
		break
	}
}

func (rt *RequestTracker) addAcceptedConnection(host, port, remoteAddr string, requestTime time.Time, rateLimitingWindowStartTime time.Time) *TrackerRequest {
	requestData, has := rt.remoteHostRequests[host]
	if !has {
		requestData = &hostIncomingRequests{
			remoteHost: host,
			requests:   make([]*TrackerRequest, 0, 1),
		}
		rt.remoteHostRequests[host] = requestData
	}
	return requestData.add(host, port, remoteAddr, requestTime, rateLimitingWindowStartTime)
}

func (rt *RequestTracker) removeAcceptedConnection(trackedRequest *TrackerRequest) {
	hostRequests := rt.remoteHostRequests[trackedRequest.remoteHost]
	if hostRequests != nil {
		hostRequests.remove(trackedRequest)
		if len(hostRequests.requests) == 0 {
			delete(rt.remoteHostRequests, trackedRequest.remoteHost)
		}
	}
}

func (rt *RequestTracker) countOriginConnections(remoteHost string, rateLimitingWindowStartTime time.Time, tcpRequestsOnly bool) uint {
	if requestData, has := rt.remoteHostRequests[remoteHost]; has {
		return requestData.countConnections(rateLimitingWindowStartTime, tcpRequestsOnly)
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

	return rt.acceptedConnections[request.RemoteAddr]
}

func (rt *RequestTracker) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// this function is called only after we've fetched all the headers. on some malicious clients, this could get delayed, so we can't rely on the
	// tcp-connection established time to align with current time.
	rateLimitingWindowStartTime := time.Now().Add(-time.Duration(rt.config.ConnectionsRateLimitingWindowSeconds) * time.Second)

	trackedRequest := rt.updateRequestRemoteAddr(request, rateLimitingWindowStartTime)
	if trackedRequest == nil {
		rt.log.Errorf("missing entry for %s in acceptedConnection map", request.RemoteAddr)
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	trackedRequest.request = request
	trackedRequest.otherTelemetryGUID, trackedRequest.otherInstanceName, trackedRequest.otherPublicAddr = getCommonHeaders(request.Header)

	rt.remoteHostRequestsMu.Lock()
	originConnections := rt.countOriginConnections(trackedRequest.remoteHost, rateLimitingWindowStartTime, false)
	rt.remoteHostRequestsMu.Unlock()

	if originConnections > rt.config.ConnectionsRateLimitingCount && rt.config.ConnectionsRateLimitingWindowSeconds > 0 && rt.config.ConnectionsRateLimitingCount > 0 {
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "incoming_connection_per_ip_rate_limit"})

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

	rt.acceptedConnectionsMu.Lock()
	defer rt.acceptedConnectionsMu.Unlock()
	// now that we're done with it, we can remove the trackedRequest from the acceptedConnections.
	delete(rt.acceptedConnections, trackedRequest.remoteAddr)

}

func (rt *RequestTracker) updateRequestRemoteAddr(request *http.Request, rateLimitingWindowStartTime time.Time) (trackedRequest *TrackerRequest) {
	rt.acceptedConnectionsMu.Lock()
	trackedRequest = rt.acceptedConnections[request.RemoteAddr]
	rt.acceptedConnectionsMu.Unlock()
	originIP := rt.getForwardedConnectionAddress(request.Header)
	if originIP == nil || trackedRequest == nil {
		return
	}

	originalTrackedRequest := trackedRequest
	origin := originIP.String()
	request.RemoteAddr = origin + ":" + originalTrackedRequest.remotePort

	rt.remoteHostRequestsMu.Lock()
	rt.removeAcceptedConnection(originalTrackedRequest)
	// add the tracking with the new address
	trackedRequest = rt.addAcceptedConnection(origin, trackedRequest.remotePort, request.RemoteAddr, trackedRequest.created, rateLimitingWindowStartTime)
	rt.remoteHostRequestsMu.Unlock()

	rt.acceptedConnectionsMu.Lock()
	defer rt.acceptedConnectionsMu.Unlock()
	delete(rt.acceptedConnections, originalTrackedRequest.remoteAddr)
	rt.acceptedConnections[trackedRequest.remoteAddr] = trackedRequest
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
