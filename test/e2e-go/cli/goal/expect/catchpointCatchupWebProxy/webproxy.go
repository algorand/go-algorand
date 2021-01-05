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

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

var webProxyDestination = flag.String("targetEndpoint", "", "target endpoint")
var webProxyRuntime = flag.Int64("runtime", 60, "how many seconds we need to run")
var webProxyRequestDelay = flag.Int64("requestDelay", 0, "how many milliseconds we're going to delay before forwarding the request")
var webProxyLogFile = flag.String("log", "webProxy.log", "optional name of log file")

func printHelp() {
	fmt.Printf("catchpoint catchup web proxy testing utility\n")
	fmt.Printf("command line arguments:\n")
	flag.PrintDefaults()

}
func main() {
	flag.Parse()
	if *webProxyDestination == "" {
		printHelp()
		return
	}
	var mu deadlock.Mutex
	wp, err := fixtures.MakeWebProxy(*webProxyDestination, func(response http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
		mu.Lock()
		time.Sleep(time.Duration(*webProxyRequestDelay) * time.Millisecond)
		mu.Unlock()
		// prevent requests for block #2 to go through.
		if strings.HasSuffix(request.URL.String(), "/block/2") {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if *webProxyLogFile != "" {
			f, _ := os.OpenFile(*webProxyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.Write([]byte(fmt.Sprintf("proxy saw request for %s\n", request.URL.String())))
			f.Close()
		}

		next(response, request)
	})
	if err != nil {
		return
	}
	defer wp.Close()
	fmt.Printf("%s\n", wp.GetListenAddress())

	// Handle signals cleanly
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)

	select {
	case sig := <-c:
		fmt.Printf("Exiting webproxy on %v\n", sig)
	case <-time.After(time.Duration(*webProxyRuntime) * time.Second):
	}
}
