// Copyright (C) 2019-2022 Algorand, Inc.
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

package internal_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/txntest"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var appSource = main(`
		txn ApplicationArgs 0
        byte "create"			// create box named arg[1]
        ==
        bz del
		int 24
        txn NumAppArgs
        int 2
        ==
        bnz default
        pop						// get rid of 24
        txn ApplicationArgs 2
        btoi
     default:
		txn ApplicationArgs 1
		box_create
        b end
     del:						// delete box arg[1]
		txn ApplicationArgs 0
        byte "delete"
        ==
        bz set
		txn ApplicationArgs 1
		box_del
        b end
     set:						// put arg[1] at start of box arg[0]
		txn ApplicationArgs 0
        byte "set"
        ==
        bz test
		txn ApplicationArgs 1
        int 0
		txn ApplicationArgs 2
		box_replace
        b end
     test:						// fail unless arg[2] is the prefix of box arg[1]
		txn ApplicationArgs 0
        byte "check"
        ==
        bz bad
		txn ApplicationArgs 1
        int 0
		txn ApplicationArgs 2
        len
		box_extract
		txn ApplicationArgs 2
        ==
        assert
        b end
     bad:
        err
`)

// TestBoxCreate tests MBR changes around allocation, deallocation
func TestBoxCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// boxes begin in 33
	testConsensusRange(t, 33, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		// increment for a size 24 box with 4 letter name
		const mbr = 2500 + 28*400

		appIndex := dl.fundedApp(addrs[0], 100_000+3*mbr, appSource)

		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appIndex,
		}

		adam := call.Args("create", "adam")
		dl.txn(adam)
		dl.txn(adam.Args("check", "adam", "\x00\x00"))
		dl.txgroup("exists", adam.Noted("one"), adam.Noted("two"))
		bobo := call.Args("create", "bobo")
		dl.txn(bobo)
		dl.txgroup("exists", bobo.Noted("one"), bobo.Noted("two"))

		dl.beginBlock()
		chaz := call.Args("create", "chaz")
		dl.txn(chaz)
		dl.txn(chaz.Noted("again"), "exists")
		dl.endBlock()

		// new block
		dl.txn(chaz.Noted("again"), "exists")
		dl.txn(call.Args("create", "dogg"), "below min")
		dl.txn(call.Args("delete", "chaz"))
		dl.txn(call.Args("delete", "chaz"), "does not exist")
		dl.txn(call.Args("create", "dogg"))
		dl.txn(call.Args("delete", "bobo"))
		empty := call.Args("create", "")
		dl.txn(empty)

	})

}

// TestBoxRW tests reading writing boxes in consecutive transactions
func TestBoxRW(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// boxes begin in 33
	testConsensusRange(t, 33, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		var bufNewLogger bytes.Buffer
		log := logging.NewLogger()
		log.SetOutput(&bufNewLogger)

		appIndex := dl.fundedApp(addrs[0], 1_000_000, appSource)
		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appIndex,
		}

		dl.txn(call.Args("create", "x", "\x10"))    // 16
		dl.txn(call.Args("set", "x", "ABCDEFGHIJ")) // 10 long
		dl.txn(call.Args("check", "x", "ABCDE"))
		dl.txn(call.Args("check", "x", "ABCDEFGHIJ"))
		dl.txn(call.Args("check", "x", "ABCDEFGHIJ\x00"))

		dl.txn(call.Args("delete", "x"))
		dl.txn(call.Args("check", "x", "ABC"), "x does not exist")
		dl.txn(call.Args("create", "x", "\x08"))
		dl.txn(call.Args("check", "x", "\x00")) // it was cleared
		dl.txn(call.Args("set", "x", "ABCDEFGHIJ"), "replace range")
		dl.txn(call.Args("check", "x", "\x00")) // still clear
		dl.txn(call.Args("set", "x", "ABCDEFGH"))
		dl.txn(call.Args("check", "x", "ABCDEFGH\x00"), "extract range")
		dl.txn(call.Args("check", "x", "ABCDEFGH"))
		dl.txn(call.Args("set", "x", "ABCDEFGHI"), "replace range")

		// Advance more than 320 rounds, ensure box is still there
		for i := 0; i < 330; i++ {
			dl.fullBlock()
		}
		time.Sleep(5 * time.Second) // balancesFlushInterval, so commit happens
		dl.fullBlock(call.Args("check", "x", "ABCDEFGH"))
		time.Sleep(100 * time.Millisecond) // give commit time to run, and prune au caches
		dl.fullBlock(call.Args("check", "x", "ABCDEFGH"))

		fmt.Printf("LOG %s\n", bufNewLogger.String())

		dl.txn(call.Args("create", "yy"))
		dl.txn(call.Args("create", "zzz"))
	})
}
