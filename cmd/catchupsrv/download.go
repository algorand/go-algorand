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
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	tools_network "github.com/algorand/go-algorand/tools/network"
)

var downloadFlag = flag.Bool("download", false, "Download blocks from an origin server")
var serversFlag = flag.String("servers", "", "Semicolon-separated list of origin server addresses (host:port)")
var networkFlag = flag.String("network", "", "Network ID to obtain servers via DNS SRV")
var genesisFlag = flag.String("genesis", "", "Genesis ID")
var connsFlag = flag.Int("conns", 2, "Number of connections per server")

var serverList []string
var nextBlk uint64

func blockToString(blk uint64) string {
	return strconv.FormatUint(blk, 36)
}

func blockDir() string {
	return filepath.Join(*dirFlag, fmt.Sprintf("v1/%s/block", *genesisFlag))
}

func blockFile(blk uint64) string {
	return filepath.Join(blockDir(), blockToString(blk))
}

func blockURL(server string, blk uint64) string {
	return fmt.Sprintf("http://%s/v1/%s/block/%s", server, *genesisFlag, blockToString(blk))
}

func fetchBlock(server string, blk uint64) error {
	fn := blockFile(blk)
	_, err := os.Stat(fn)
	if err == nil {
		return nil
	}

	if !os.IsNotExist(err) {
		return err
	}

	fmt.Printf("Fetching %d from %s..\n", blk, server)
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

	return ioutil.WriteFile(fn, body, 0666)
}

func fetcher(server string, wg *sync.WaitGroup) {
	for {
		myBlock := atomic.AddUint64(&nextBlk, 1) - 1

		err := fetchBlock(server, myBlock)
		if err != nil {
			fmt.Printf("Fetching %d from %s: %v\n", myBlock, server, err)
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
			resolver.DNSAddress = *dnsAddr
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

	os.MkdirAll(blockDir(), 0777)

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
