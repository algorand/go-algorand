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

// generate a new p2p private key and print out peerID to stdout

package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/util"
	"github.com/libp2p/go-libp2p/core/peer"
)

var dataDirectory = flag.String(
	"d", "",
	"Optional root Algorand data path or a path to a directory where the private key will be stored.\n"+
		"Default directory is the current directory. Private key name is '"+p2p.DefaultPrivKeyPath+"'",
)

func main() {
	flag.Parse()
	dataDir := *dataDirectory
	if dataDir == "" {
		dataDir = "."
	}

	exist := false
	privKeyPath := path.Join(dataDir, p2p.DefaultPrivKeyPath)
	if util.FileExists(privKeyPath) {
		exist = true
	}

	peerKey, err := p2p.GetPrivKey(config.Local{P2PPersistPeerID: true}, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error obtaining private key: %v\n", err)
		os.Exit(1)
	}
	peerID, err := peer.IDFromPublicKey(peerKey.GetPublic())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error obtaining peerID from a key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("PeerID: %s\n", peerID.String())
	if !exist {
		fmt.Printf("Private key saved to %s\n", privKeyPath)
	} else {
		fmt.Printf("Used existing key %s\n", privKeyPath)
	}
}
