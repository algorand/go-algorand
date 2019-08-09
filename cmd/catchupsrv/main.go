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

package main

import (
	"flag"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"

	"github.com/algorand/websocket"
	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/rpcs"
)

var addrFlag = flag.String("addr", "127.0.0.1:4160", "Address to listen on")
var dirFlag = flag.String("dir", "", "Directory containing catchup blocks")

func main() {
	flag.Parse()

	log := logging.Base()
	log.SetLevel(logging.Info)

	if *dirFlag == "" {
		panic("Must specify -dir")
	}

	if *downloadFlag {
		download()
		return
	}

	var srv http.Server
	r := mux.NewRouter()
	srv.Handler = r
	srv.Addr = *addrFlag

	var upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	r.HandleFunc(network.GossipNetworkPath, func(w http.ResponseWriter, r *http.Request) {
		pathVars := mux.Vars(r)
		genesisID := pathVars["genesisID"]

		requestHeader := make(http.Header)
		requestHeader.Set(network.GenesisHeader, genesisID)
		requestHeader.Set(network.ProtocolVersionHeader, "1")

		conn, err := upgrader.Upgrade(w, r, requestHeader)
		if err != nil {
			return
		}

		go func() {
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					break
				}
			}
		}()
	})

	r.HandleFunc(rpcs.LedgerServiceBlockPath, func(w http.ResponseWriter, r *http.Request) {
		pathVars := mux.Vars(r)
		versionStr := pathVars["version"]
		roundStr := pathVars["round"]
		genesisID := pathVars["genesisID"]

		blkPath, err := stringBlockToPath(roundStr)
		if err != nil {
			log.Infof("%s %s: %v", r.Method, r.URL, err)
			http.NotFound(w, r)
			return
		}

		data, err := ioutil.ReadFile(
			path.Join(
				*dirFlag,
				"v"+versionStr,
				genesisID,
				"block",
				blkPath,
			),
		)
		if err != nil {
			log.Infof("%s %s: %v", r.Method, r.URL, err)
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/x-algorand-block-v1")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	})

	err := srv.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
