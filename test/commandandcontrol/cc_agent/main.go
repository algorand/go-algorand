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

// cc_agent starts agent process on algod host
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/commandandcontrol/cc_agent/component"
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
var addr = flag.String("service-addr", "localhost:8080", "http service address")
var hostName = flag.String("hostname", "Host1", "host name")
var binDir = flag.String("bindir", "", "host name")
var tempDir = flag.String("tempdir", "", "host name")
var dataDirs arrayFlags

func init() {
	flag.Var(&dataDirs, "nodedir", "node data directory")
	flag.Var(&dataDirs, "d", "node data directory (shorthand)")
}

var serverChannel = make(chan []byte, 100)

func checkFlags() (ok bool) {
	ok = true
	if len(dataDirs) == 0 {
		log.Errorf("Use the -nodedir or -d flag to specify one or more node data directories")
		ok = false
	}
	if len(*binDir) == 0 {
		log.Errorf("Use the -bindir flag to specify the location of the algod bin directory")
		ok = false
	}
	if len(*tempDir) == 0 {
		log.Errorf("Use the -tempdir flag to specify the location of the tmp directory directory")
		ok = false
	}
	return ok
}

func main() {
	flag.Parse()
	log.SetLevel(logging.Debug)

	if !checkFlags() {
		os.Exit(1)
	}

	component.GetHostAgent().BinDir = *binDir
	component.GetHostAgent().TempDir = *tempDir

	// build the algo node map based on the data dirs
	algoNodeMap := make(map[string]component.AlgodNode)
	for _, dataDir := range dataDirs {
		dataDirParts := strings.Split(dataDir, "/")
		nodeName := dataDirParts[len(dataDirParts)-1]
		if nodeName == "" {
			nodeName = dataDirParts[len(dataDirParts)-2]
		}
		algodNode := component.AlgodNode{
			Name:    nodeName,
			Status:  "OK",
			DataDir: dataDir,
		}
		algoNodeMap[nodeName] = algodNode
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	component.GetHostAgent().Host = component.Host{
		Name:    *hostName,
		NodeMap: algoNodeMap,
	}

	hostConfigMessage := fmt.Sprintf("New Agent Host Config: %+v", component.GetHostAgent().Host)
	log.Infof("%s", hostConfigMessage)

	serverChannel <- []byte(hostConfigMessage)

	u := url.URL{Scheme: "ws", Host: *addr, Path: "/agent"}
	log.Infof("connecting to %s", u.String())

	serverWs, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Errorf("dial:", err)
	}
	serverWs.Unsafe = true
	defer func() {
		log.Infof("closing service websocket: %s", serverWs.LocalAddr())
		err := serverWs.Close()
		if err != nil {
			log.Errorf("error closing service websocket %v", err)
		}
	}()

	go forwardMessagesToServer(serverWs)

	component.GetHostAgent().ServiceConnection = serverWs

	done := make(chan struct{})

	// accept and process commands sent from CC Service
	go func() {
		defer close(done)
		for {
			var managementServiceRequest lib.CCServiceRequest
			err := serverWs.ReadJSON(&managementServiceRequest)
			if err != nil {
				log.Errorf("ReadJSON %v:", err)
				return
			}
			log.Infof("recv: %+v", managementServiceRequest)
			err = component.GetHostAgent().ProcessRequest(managementServiceRequest)
			if err != nil {
				log.Errorf("error processRequest: %v\n", err)
				return
			}
			serverChannel <- []byte(fmt.Sprintf("agent %s is processing request %+v", component.GetHostAgent().Host.Name, managementServiceRequest))
		}
	}()

	// Send heartbeat to CC Service
	ticker := time.NewTicker(time.Second * 60)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case t := <-ticker.C:
			err := serverWs.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("heartbeat from agent %s with time %s", component.GetHostAgent().Host.Name, t.String())))
			if err != nil {
				log.Errorf("write:", err)
				return
			}
		case <-interrupt:
			log.Infof("interrupt")
			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := serverWs.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Errorf("write close:", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

func forwardMessagesToServer(serverWs *websocket.Conn) {
	log.Infof("forwardMessagesToServer()\n")
	for {
		// Wait for the next message from the server channel
		msg := <-serverChannel

		err := serverWs.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			log.Errorf("error: %v", err)
			err = serverWs.Close()
			if err != nil {
				log.Errorf("error closing server websocket %v", err)
			}
		}
	}
}
