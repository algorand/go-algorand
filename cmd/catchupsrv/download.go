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
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	tools_network "github.com/algorand/go-algorand/tools/network"
)

const minLenBlockStr = 6 // the minimum size of a block filename (after padding with zeros) when using subfolders

var downloadFlag = flag.Bool("download", false, "Download blocks from an origin server")
var serversFlag = flag.String("servers", "", "Semicolon-separated list of origin server addresses (host:port)")
var networkFlag = flag.String("network", "", "Network ID to obtain servers via DNS SRV")
var genesisFlag = flag.String("genesis", "", "Genesis ID")
var connsFlag = flag.Int("conns", 2, "Number of connections per server")

var serverList []string
var nextBlk uint64

// padLeftZeros pad the string s with zeros on the left to the length n
func padLeftZeros(s string, n int) string {
	if len(s) < n {
		return strings.Repeat("0", n-len(s)) + s
	}
	return s
}

// blockToString converts a block number into a base-36 number
func blockToString(blk uint64) string {
	return strconv.FormatUint(blk, 36)
}

// blockToFileName converts a block number into the filename in which it will be downloaded
// namely the base-36 representation of the block number padded with zeros
// so that the length of the filename is at least minLenBlockStr
func blockToFileName(blk uint64) string {
	return padLeftZeros(blockToString(blk), minLenBlockStr)
}

// stringToBlock converts a base-36 string into a block number
func stringToBlock(s string) (uint64, error) {
	blk, err := strconv.ParseUint(s, 36, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid block string \"%s\": %v", s, err)
	}
	return blk, nil
}

// blockToPath converts a block number into the full path in which it will be downloaded
// Examples:
// - for block `bcdef`, the path is `0b/cd/0bcdef`
// - for block `abcdefg`, the path is `abc/de/abcdefg`
func blockToPath(blk uint64) string {
	s := blockToFileName(blk)
	return path.Join(
		s[0:(len(s)+2-minLenBlockStr)],
		s[(len(s)+2-minLenBlockStr):(len(s)+4-minLenBlockStr)],
		s,
	)
}

// stringBlockToPath is the same as blockToPath except it takes a (non-padded) base-36 block
func stringBlockToPath(s string) (string, error) {
	blk, err := stringToBlock(s)
	if err != nil {
		return "", err
	}
	return blockToPath(blk), nil
}

// blockDir returns the root folder where all the blocks are stored
func blockDir() string {
	return filepath.Join(*dirFlag, fmt.Sprintf("v1/%s/block", *genesisFlag))
}

// blockFullPath returns the full path to a block, including blockDir
func blockFullPath(blk uint64) string {
	return filepath.Join(blockDir(), blockToPath(blk))
}

func blockURL(server string, blk uint64) string {
	return fmt.Sprintf("http://%s/v1/%s/block/%s", server, *genesisFlag, blockToString(blk))
}

func fetchBlock(server string, blk uint64) error {
	log := logging.Base()

	fn := blockFullPath(blk)
	_, err := os.Stat(fn)
	if err == nil {
		log.Debugf("block %d already exists", blk)
		return nil
	}

	if !os.IsNotExist(err) {
		return err
	}

	log.Infof("fetching %d (%s) from %s..", blk, blockToFileName(blk), server)
	resp, err := http.Get(blockURL(server, blk))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP response: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Create the folder if needed
	d := path.Dir(fn)
	_, err = os.Stat(d)
	if os.IsNotExist(err) {
		// Create the folder if it does not exist
		err = os.MkdirAll(d, 0777)
		if err != nil {
			panic(err)
		}
	} else if err != nil {
		panic(err)
	}

	return ioutil.WriteFile(fn, body, 0666)
}

func fetcher(server string, wg *sync.WaitGroup) {
	log := logging.Base()

	for {
		myBlock := atomic.AddUint64(&nextBlk, 1) - 1

		err := fetchBlock(server, myBlock)
		if err != nil {
			log.Errorf("fetching %d (%s) from %s: %v", myBlock, blockToFileName(myBlock), server, err)
			break
		}
	}

	wg.Done()
}

func download() {
	if *genesisFlag == "" {
		panic("Must specify -genesis")
	}

	if *serversFlag != "" {
		serverList = strings.Split(*serversFlag, ";")
	} else if *networkFlag != "" {
		cfg := config.GetDefaultLocal()
		bootstrapID := cfg.DNSBootstrap(protocol.NetworkID(*networkFlag))
		_, records, err := net.LookupSRV("algobootstrap", "tcp", bootstrapID)
		if err != nil {
			dnsAddr, err2 := net.ResolveIPAddr("ip", cfg.FallbackDNSResolverAddress)
			if err2 != nil {
				// Report original LookupSRV error
				panic(err)
			}

			var resolver tools_network.Resolver
			resolver.SetFallbackResolverAddress(*dnsAddr)
			_, records, err = resolver.LookupSRV(context.Background(), "algobootstrap", "tcp", bootstrapID)
			if err != nil {
				panic(err)
			}
		}

		for _, srv := range records {
			serverList = append(serverList, fmt.Sprintf("%s:%d", srv.Target, srv.Port))
		}
	} else {
		panic("Must specify -servers or -network")
	}

	http.DefaultTransport.(*http.Transport).MaxConnsPerHost = *connsFlag
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = *connsFlag

	err := os.MkdirAll(blockDir(), 0777)
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup

	fetchPerServer := *connsFlag
	for _, srv := range serverList {
		wg.Add(fetchPerServer)
		for i := 0; i < fetchPerServer; i++ {
			go fetcher(srv, &wg)
		}
	}

	wg.Wait()
}
