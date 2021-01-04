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
	"os"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

var serverAddress = flag.String("server", "", "Server address (host:port)")
var numClients = flag.Int("num", 1, "Number of connections")
var genesisID = flag.String("genesis", "perfnet-v23", "Genesis ID")
var networkID = flag.String("network", "perfnet", "Network ID")

func main() {
	deadlock.Opts.Disable = true

	flag.Parse()

	conf, _ := config.LoadConfigFromDisk("/dev/null")
	conf.DNSBootstrapID = ""

	log := logging.Base()
	log.SetLevel(logging.Debug)
	log.SetOutput(os.Stderr)

	var nodes []network.GossipNode
	for i := 0; i < *numClients; i++ {
		n, _ := network.NewWebsocketGossipNode(log,
			conf,
			[]string{*serverAddress},
			*genesisID,
			protocol.NetworkID(*networkID))
		n.Start()
		nodes = append(nodes, n)
	}

	fmt.Printf("Created %d clients\n", *numClients)
	for {
		time.Sleep(time.Second)
	}
}
