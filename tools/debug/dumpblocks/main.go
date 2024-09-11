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

package main

import (
	"database/sql"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var blockDBfile = flag.String("blockdb", "", "Block DB filename")
var numBlocks = flag.Int("numblocks", 10000, "Randomly sample this many blocks for training")
var startRound = flag.Int("start", 0, "Sample blocks starting at this round (inclusive)")
var endRound = flag.Int("end", 0, "Sample blocks ending at this round (inclusive)")
var outDir = flag.String("outdir", ".", "Write blocks to this directory")
var randSeed = flag.Int("seed", 0, "Random seed, otherwise will use time")

func getBlockToFile(db *sql.DB, rnd int64) error {
	var buf []byte
	err := db.QueryRow("SELECT blkdata FROM blocks WHERE rnd=?", rnd).Scan(&buf)
	if err != nil {
		return err
	}
	return os.WriteFile(fmt.Sprintf("%s/%d.block", *outDir, rnd), buf, 0644)
}

func usage() {
	flag.Usage()
	os.Exit(1)
}

func main() {
	flag.Parse()
	if *blockDBfile == "" {
		fmt.Println("-blockdb=file required")
		usage()
	}
	uri := fmt.Sprintf("file:%s?_journal_mode=wal", *blockDBfile)
	fmt.Println("Opening", uri)
	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	seed := int64(*randSeed)
	if seed == 0 {
		seed = time.Now().UnixMicro()
	}
	rand.Seed(seed)

	var minRound, maxRound int64
	if *startRound != 0 {
		minRound = int64(*startRound)
	}
	if *endRound != 0 {
		maxRound = int64(*endRound)
	}
	if maxRound == 0 {
		err = db.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&maxRound)
		if err != nil {
			panic(err)
		}
	}
	if minRound == 0 {
		err = db.QueryRow("SELECT MIN(rnd) FROM blocks").Scan(&minRound)
		if err != nil {
			panic(err)
		}
	}

	N := maxRound - minRound
	if N <= 0 {
		panic("maxRound must be greater than minRound")
	}

	if N <= int64(*numBlocks) {
		// just get all blocks from minRound to maxRound
		fmt.Printf("Saving all blocks between round %d and %d\n", minRound, maxRound)
		for i := minRound; i <= maxRound; i++ {
			err = getBlockToFile(db, i)
			if err != nil {
				panic(err)
			}

		}
		os.Exit(0)
	}

	fmt.Printf("Loading %d random blocks between round %d and %d\n", *numBlocks, minRound, maxRound)
	for i := 0; i < *numBlocks; i++ {
		round := minRound + rand.Int63n(N) + 1
		err = getBlockToFile(db, round)
		if err != nil {
			panic(err)
		}
	}
}
