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
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

// RequestLogger is a middleware helps logging all the incoming http requests.
// The intended use is to place it at the bottom of the http processing. It will capture the status codes
// set by the upstream handlers and write the request info/response to the logger.
type RequestLogger struct {
	downsteamHandler    http.Handler
	trackingWritersPool sync.Pool
	log                 logging.Logger
}

// create a RequestLogger object.
func makeRequestLogger(downsteamHandler http.Handler, log logging.Logger) *RequestLogger {
	rl := &RequestLogger{
		downsteamHandler: downsteamHandler,
		log:              log,
	}
	rl.trackingWritersPool = sync.Pool{
		New: func() interface{} {
			return &trackingResponseWriter{}
		},
	}
	return rl
}

// this is the http entry point for the request logger.
func (rl *RequestLogger) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	trackingWriter := rl.trackingWritersPool.Get().(*trackingResponseWriter)
	trackingWriter.Reset(writer)
	defer func() {
		// log the request.
		rl.logRequest(trackingWriter, request)
		// reset with nil to allow the GC to recycle the underlaying writer.
		trackingWriter.Reset(nil)
		rl.trackingWritersPool.Put(trackingWriter)
	}()
	rl.downsteamHandler.ServeHTTP(trackingWriter, request)
}

// log the request that was tracked, including the resulting error code.
func (rl *RequestLogger) logRequest(trackingWriter *trackingResponseWriter, request *http.Request) {
	uri := request.RequestURI
	if len(uri) > 64 {
		uri = uri[:64]
	}
	requestDetails := telemetryspec.HTTPRequestDetails{
		Client:       strings.Split(request.RemoteAddr, ":")[0],
		InstanceName: request.Header.Get(InstanceNameHeader),
		Request:      fmt.Sprintf("%s %s %s", request.Method, uri, request.Proto),
		StatusCode:   uint64(trackingWriter.statusCode),
		BodyLength:   uint64(trackingWriter.contentLen),
		UserAgent:    request.Header.Get(UserAgentHeader),
	}
	rl.log.EventWithDetails(telemetryspec.Network, telemetryspec.HTTPRequestEvent, requestDetails)
}

// SetStatusCode sets the status code of a given response writer without writing it to the underlaying writer object.
func (rl *RequestLogger) SetStatusCode(writer http.ResponseWriter, statusCode int) {
	if trackingWriter := writer.(*trackingResponseWriter); trackingWriter != nil {
		trackingWriter.statusCode = statusCode
	}
}

type trackingResponseWriter struct {
	writer     http.ResponseWriter
	statusCode int
	contentLen int
}

func (trw *trackingResponseWriter) Header() http.Header {
	return trw.writer.Header()
}

func (trw *trackingResponseWriter) Write(b []byte) (n int, err error) {
	if trw.statusCode == 0 {
		trw.statusCode = http.StatusOK
	}
	n, err = trw.writer.Write(b)
	trw.contentLen += n
	return
}

func (trw *trackingResponseWriter) WriteHeader(statusCode int) {
	trw.writer.WriteHeader(statusCode)
	trw.statusCode = statusCode
}

func (trw *trackingResponseWriter) Reset(writer http.ResponseWriter) {
	trw.statusCode = 0
	trw.contentLen = 0
	trw.writer = writer
}

func (trw *trackingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijack := trw.writer.(http.Hijacker)
	if hijack == nil {
		// not implemented; doesn't really happen, but we want this for code-complete
		return nil, nil, fmt.Errorf("writer doesn't implement Hijacker interface")
	}

	return hijack.Hijack()
}
