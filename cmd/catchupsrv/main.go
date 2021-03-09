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
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/algorand/websocket"
	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/rpcs"
)

var addrFlag = flag.String("addr", "127.0.0.1:4160", "Address to listen on")
var dirFlag = flag.String("dir", "", "Directory containing catchup blocks")
var tarDirFlag = flag.String("tardir", "", "Directory containing catchup blocks in M_N.tar.bz2")

func main() {
	flag.Parse()

	log := logging.Base()
	log.SetLevel(logging.Info)

	if *dirFlag == "" && *tarDirFlag == "" {
		panic("Must specify -dir or -tardir")
	}

	var blocktars *tarBlockSet
	if *tarDirFlag != "" {
		var err error
		blocktars, err = openTarBlockDir(*tarDirFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: error opening block tar dir, %v\n", *tarDirFlag, err)
			os.Exit(1)
		}
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

		var rnd [10]byte
		crypto.RandBytes(rnd[:])

		requestHeader := make(http.Header)
		requestHeader.Set(network.GenesisHeader, genesisID)
		requestHeader.Set(network.NodeRandomHeader, base64.StdEncoding.EncodeToString(rnd[:]))
		requestHeader.Set(network.ProtocolVersionHeader, "2.1")

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

	r.HandleFunc(rpcs.BlockServiceBlockPath, func(w http.ResponseWriter, r *http.Request) {
		pathVars := mux.Vars(r)
		versionStr := pathVars["version"]
		roundStr := pathVars["round"]
		genesisID := pathVars["genesisID"]

		roundNumber, err := stringToBlock(roundStr)
		if err != nil {
			log.Infof("%s %s: %v", r.Method, r.URL, err)
			http.NotFound(w, r)
			return
		}

		var data []byte
		if *dirFlag != "" {
			blkPath := blockToPath(roundNumber)
			data, err = ioutil.ReadFile(
				path.Join(
					*dirFlag,
					"v"+versionStr,
					genesisID,
					"block",
					blkPath,
				),
			)
		} else if blocktars != nil {
			data, err = blocktars.getBlock(roundNumber)
		} else {
			fmt.Fprintf(os.Stderr, "config err, no block dir and no block tar dir\n")
			defer os.Exit(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err != nil {
			log.Infof("%s %s: %v", r.Method, r.URL, err)
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/x-algorand-block-v1")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		if rand.Intn(20) == 0 {
			log.Infof("OK %d", roundNumber)
		}
	})

	log.Infof("serving %s", srv.Addr)
	err := srv.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
