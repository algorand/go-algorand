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
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
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
		dl.txn(adam, "invalid Box reference adam")
		adam.Boxes = []transactions.BoxRef{{Index: 0, Name: "adam"}}
		dl.txn(adam)
		dl.txn(adam.Args("check", "adam", "\x00\x00"))
		dl.txgroup("exists", adam.Noted("one"), adam.Noted("two"))
		bobo := call.Args("create", "bobo")
		dl.txn(bobo, "invalid Box reference bobo")
		bobo.Boxes = []transactions.BoxRef{{Index: 0, Name: "bobo"}}
		dl.txn(bobo)
		dl.txgroup("exists", bobo.Noted("one"), bobo.Noted("two"))

		dl.beginBlock()
		chaz := call.Args("create", "chaz")
		chaz.Boxes = []transactions.BoxRef{{Index: 0, Name: "chaz"}}
		dl.txn(chaz)
		dl.txn(chaz.Noted("again"), "exists")
		dl.endBlock()

		// new block
		dl.txn(chaz.Noted("again"), "exists")
		dogg := call.Args("create", "dogg")
		dogg.Boxes = []transactions.BoxRef{{Index: 0, Name: "dogg"}}
		dl.txn(dogg, "below min")
		dl.txn(chaz.Args("delete", "chaz"))
		dl.txn(chaz.Args("delete", "chaz").Noted("again"), "does not exist")
		dl.txn(dogg)
		dl.txn(bobo.Args("delete", "bobo"))

		// empty name is legal
		empty := call.Args("create", "")
		dl.txn(empty, "invalid Box reference")
		empty.Boxes = []transactions.BoxRef{{}}
		dl.txn(empty)
	})
}

func TestBoxCreateAvailability(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// boxes begin in 33
	testConsensusRange(t, 33, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		accessInCreate := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: 0, // This is a create
			Boxes:         []transactions.BoxRef{{Index: 0, Name: "hello"}},
			ApprovalProgram: `
              int 10
              byte "hello"
              box_create
              int 1
`,
		}

		// We know box_create worked because we finished and checked MBR
		dl.txn(&accessInCreate, "balance 0 below min")

		// But let's fund it and be sure. This is "psychic". We're going to fund
		// the app address that we know the app will get. So this is a nice
		// test, but unrealistic way to actual create a box.
		psychic := basics.AppIndex(2)
		dl.txn(&txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: psychic.Address(),
			Amount:   108501,
		})
		dl.txn(&accessInCreate)

		// Now, a more realistic, though tricky, way to get a box created during
		// the app's first txgroup in existence is to create it in tx0, and then
		// in tx1 fund it using an inner tx, then invoke it with an inner
		// transaction. During that invocation, the app will have access to the
		// boxes supplied as "0 refs", since they were resolved to the app ID
		// during creation.

		accessWhenCalled := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: 0, // This is a create
			Boxes:         []transactions.BoxRef{{Index: 0, Name: "hello"}},
			// Note that main() wraps the program so it does not run at creation time.
			ApprovalProgram: main(`
              int 10
              byte "hello"
              box_create
              byte "we did it"
              log
`),
		}

		trampoline := dl.fundedApp(addrs[0], 1_000_000, main(`
            // Fund the app created in the txn behind me.
			txn GroupIndex
            int 1
            -
            gtxns CreatedApplicationID
            dup					// copy for use when calling
            dup					// test copy
            assert
            app_params_get AppAddress
            assert

            itxn_begin
             itxn_field Receiver
             int 500000
             itxn_field Amount
             int pay
             itxn_field TypeEnum
            itxn_submit

            // Now invoke it, so it can intialize (and create the "hello" box)
            itxn_begin
             itxn_field ApplicationID
             int appl
             itxn_field TypeEnum
            itxn_submit
`))

		call := txntest.Txn{
			Sender:        addrs[0],
			Type:          "appl",
			ApplicationID: trampoline,
		}

		dl.beginBlock()
		dl.txgroup("", &accessWhenCalled, &call)
		vb := dl.endBlock()

		// Make sure that we actually did it.
		require.Equal(t, "we did it", vb.Block().Payset[1].ApplyData.EvalDelta.InnerTxns[1].EvalDelta.Logs[0])
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
			Boxes:         []transactions.BoxRef{{Index: 0, Name: "x"}},
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

		dl.txn(call.Args("create", "yy"), "invalid Box reference yy")
		withBr := call.Args("create", "yy")
		withBr.Boxes = append(withBr.Boxes, transactions.BoxRef{Index: 1, Name: "yy"})
		require.Error(dl.t, withBr.Txn().WellFormed(transactions.SpecialAddresses{}, dl.generator.GenesisProto()))
		withBr.Boxes[1].Index = 0
		dl.txn(withBr)
	})
}
