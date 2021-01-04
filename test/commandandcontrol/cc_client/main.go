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
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"

	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/commandandcontrol/lib"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var log = logging.NewLogger()

var targetHosts arrayFlags
var addr = flag.String("service-addr", "localhost:8080", "CC service address")
var componentName = flag.String("component", "pingpong", "name of component to control")
var componentAction = flag.String("action", "start", "action to perform (start or stop)")
var componentOptions = flag.String("options", "", "json configuration file for component action")
var listen = flag.Bool("listen", false, "keep connection to server open and tail output")

func main() {
	flag.Var(&targetHosts, "target", "target host:node, wildcards(*) are supported for host and node")
	flag.Parse()
	log.SetLevel(logging.Debug)

	if len(targetHosts) == 0 {
		log.Errorf("Use the --target flag to specify one or more target host:node pairs")
		os.Exit(1)
	}

	if *componentOptions == "" {
		log.Errorf("Use the --options flag to specify the command options")
		os.Exit(1)
	}

	options, err := ioutil.ReadFile(*componentOptions)
	if err != nil {
		log.Errorf("failed to read options file %s", *componentOptions)
	}
	log.Infof("starting client with options %s", options)

	u := url.URL{Scheme: "ws", Host: *addr, Path: "/client"}
	log.Infof("connecting to cc service: %s", u.String())

	serverWs, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer func() {
		log.Infof("closing service connection: %s", serverWs.RemoteAddr())
		err := serverWs.Close()
		if err != nil {
			log.Fatalf("error closing service websocket %v", err)
		}
	}()
	serverWs.Unsafe = true

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			// sig is a ^C
			log.Errorf("received signal %+v", sig)
			closeServiceConnection(serverWs)
			os.Exit(1)
		}
	}()

	ccServiceRequest := lib.CCServiceRequest{
		Component:       *componentName,
		Command:         *componentAction,
		Parameters:      fmt.Sprintf("%s", options),
		TargetAgentList: targetHosts,
	}

	log.Infof("sending service request to %+v", ccServiceRequest)
	err = serverWs.WriteJSON(ccServiceRequest)
	if err != nil {
		log.Fatalf("sending service request resulted in error: %v", err)
	}

	for {
		messageType, response, err := serverWs.ReadMessage()
		if err != nil {
			log.Fatalf("reading service response returned error: %v", err)
		} else if messageType == websocket.TextMessage {
			log.Infof("Response: %s", response)
		} else {
			log.Infof("Response: %+v", response)
		}
		if *listen == false {
			break
		}
	}
	closeServiceConnection(serverWs)
}

func closeServiceConnection(serverWs *websocket.Conn) {
	err := serverWs.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Errorf("write close:", err)
		return
	}
}
