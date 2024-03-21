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

package fixtures

import (
	"net"
	"net/http"
	"strings"

	"github.com/algorand/go-algorand/logging"
)

// WebProxyInterceptFunc expose the web proxy intercept function
type WebProxyInterceptFunc func(http.ResponseWriter, *http.Request, http.HandlerFunc)

// WebProxy is the web proxy instance
type WebProxy struct {
	server      *http.Server
	listener    net.Listener
	destination string
	intercept   WebProxyInterceptFunc
	log         logging.Logger
}

// MakeWebProxy creates an instance of the web proxy
func MakeWebProxy(destination string, log logging.Logger, intercept WebProxyInterceptFunc) (wp *WebProxy, err error) {
	destination = strings.TrimPrefix(destination, "http://")
	wp = &WebProxy{
		destination: destination,
		intercept:   intercept,
		log:         log,
	}
	wp.server = &http.Server{
		Handler: wp,
	}
	wp.listener, err = net.Listen("tcp", "localhost:")
	if err != nil {
		return nil, err
	}
	go func() {
		wp.server.Serve(wp.listener)
	}()
	return wp, nil
}

// GetListenAddress retrieves the listening address of the web proxy
func (wp *WebProxy) GetListenAddress() string {
	return wp.listener.Addr().String()
}

// Close release the web proxy resources
func (wp *WebProxy) Close() {
	wp.log.Debugln("webproxy: quiting")
	// we can't use shutdown, since we have tunneled websocket, which is a hijacked connection
	// that http.Server doens't know how to handle.
	wp.server.Close()
}

// ServeHTTP serves a single HTTP request
func (wp *WebProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	wp.log.Debugf("webproxy: incoming request for %v", request.URL)
	if wp.intercept == nil {
		wp.Passthrough(response, request)
		return
	}
	wp.intercept(response, request, wp.Passthrough)
}

// Passthrough is the default web proxy implemented function for passing a requests through without modifying it.
func (wp *WebProxy) Passthrough(response http.ResponseWriter, request *http.Request) {
	client := http.Client{}
	clientRequestURL := *request.URL
	clientRequestURL.Scheme = "http"
	clientRequestURL.Host = wp.destination
	clientRequest, err := http.NewRequest(request.Method, clientRequestURL.String(), request.Body)
	if err != nil {
		wp.log.Debugf("Passthrough request assembly error %v (%#v)", err, clientRequestURL)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	if request.Header != nil {
		for headerKey, headerValues := range request.Header {
			for _, headerValue := range headerValues {
				clientRequest.Header.Add(headerKey, headerValue)
			}
		}
	}
	clientResponse, err := client.Do(clientRequest)
	if err != nil {
		wp.log.Debugf("Passthrough request error %v (%v)", err, request.URL.String())
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	if clientResponse.Header != nil {
		for headerKey, headerValues := range clientResponse.Header {
			for _, headerValue := range headerValues {
				response.Header().Add(headerKey, headerValue)
			}
		}
	}
	response.WriteHeader(clientResponse.StatusCode)
	ch := make(chan []byte, 10)
	go func(outCh chan []byte) {
		defer close(outCh)
		if clientResponse.Body == nil {
			return
		}
		defer clientResponse.Body.Close()
		for {
			buf := make([]byte, 4096)
			n, err := clientResponse.Body.Read(buf)
			if n > 0 {
				outCh <- buf[:n]
			}
			if err != nil {
				break
			}

		}
	}(ch)
	for bytes := range ch {
		response.Write(bytes)
		if flusher, has := response.(http.Flusher); has {
			flusher.Flush()
		}
	}
}
