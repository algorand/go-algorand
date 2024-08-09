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

// pender benchmarks pending transactions REST API performance
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
)

var address = flag.String("addr", "", "Server rest address (host:port)")
var token = flag.String("token", "", "Server token for rest endpoint (optional)")

func fatal(msg string, args ...any) {
	fmt.Println(msg, args)
	os.Exit(1)
}

func main() {

	flag.Parse()
	if *address == "" {
		fatal("-addr=address required")
	}

	var url string
	var maxReq int64
	txID := transactions.Txid{}
	crypto.RandBytes(txID[:])
	strID := "UCPICZH6FWMZVPJH7X4IV6M2WZZQCRX7ETIQK742BQMCDP5TVNEQ"
	url = fmt.Sprintf("http://%s/v2/transactions/pending/%s", *address, strID)
	maxReq = 100

	httpClient := http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: int(maxReq)}}
	var limit atomic.Int64
	var count atomic.Int64
	fmt.Printf("using url: %s\n", url)
	start := time.Now()
	go func() {
		t := time.NewTicker(5 * time.Second)
		curStart := time.Now()
		curCount := count.Load()
		for {
			<-t.C
			dt := time.Since(curStart)
			num := count.Load() - curCount
			curStart = time.Now()
			curCount = count.Load()
			fmt.Printf("elapsed: %s, req/s: %f\n", time.Since(start), float64(num)/dt.Seconds())
		}
	}()

	for {
		if limit.Load() < maxReq {
			count.Add(1)
			val := limit.Add(1)
			go func(idx int64) {
				defer limit.Add(-1)
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					fatal("new req error:", err)
				}
				req.Header.Set("X-Algo-API-Token", *token)

				resp, err := httpClient.Do(req)
				if err != nil {
					fatal("do error:", idx, err)
				}
				defer resp.Body.Close()
				buf, _ := io.ReadAll(resp.Body)
				if len(buf) == 0 {
					fmt.Println("status:", idx, resp.Status, len(buf))
				}
			}(val)
		}
	}
}
