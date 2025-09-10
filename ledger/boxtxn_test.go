// Copyright (C) 2019-2025 Algorand, Inc.
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

package ledger

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

var boxAppSource = main(`
		txn ApplicationArgs 0
        byte "create"			// create box named arg[1]
        ==
		txn ApplicationArgs 0
		byte "recreate"
		==
		||
        bz del
		txn ApplicationArgs 1
		int 24
        txn NumAppArgs
        int 2
        ==
        bnz default
        pop						// get rid of 24
        txn ApplicationArgs 2
        btoi
     default:
		txn ApplicationArgs 0
		byte "recreate"
		==
		bz first
		box_create
		!
		assert
		b end
	 first:
	    box_create
        assert
        b end
     del:						// delete box arg[1]
		txn ApplicationArgs 0; byte "delete"; ==
        bz set
		txn ApplicationArgs 1
		box_del
        assert
        b end
     set:						// put arg[2] at start of box arg[1]
		txn ApplicationArgs 0; byte "set"; ==
        bz put
		txn ApplicationArgs 1
        int 0
		txn ApplicationArgs 2
		box_replace
        b end
     put:						// box_put arg[2] as replacement for box arg[1]
		txn ApplicationArgs 0; byte "put"; ==
        bz get
		txn ApplicationArgs 1
		txn ApplicationArgs 2
		box_put
        b end
     get:						// log box arg[1], after getting it with box_get
		txn ApplicationArgs 0; byte "get"; ==
        bz check
		txn ApplicationArgs 1
		box_get
        assert
        log
        b end
     check:						// fail unless arg[2] is the prefix of box arg[1]
		txn ApplicationArgs 0; byte "check"; ==
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

// Call the app in txn.Applications[1] the same way I was called.
var passThruSource = main(`
  itxn_begin
  txn Applications 1; itxn_field ApplicationID
  txn TypeEnum; itxn_field TypeEnum
  // copy my app args into itxn app args (too lazy to write a loop), these are
  // always called with 2 or 3 args.
  txn ApplicationArgs 0; itxn_field ApplicationArgs
  txn ApplicationArgs 1; itxn_field ApplicationArgs
  txn NumAppArgs; int 2; ==; bnz skip
    txn ApplicationArgs 2; itxn_field ApplicationArgs
  skip:
  itxn_submit
`)

const (
	boxVersion          = 36
	accessVersion       = 38
	boxQuotaBumpVersion = 41
	newAppCreateVersion = 41
)

func boxFee(p config.ConsensusParams, nameAndValueSize uint64) uint64 {
	return p.BoxFlatMinBalance + p.BoxByteMinBalance*(nameAndValueSize)
}

// TestBoxCreate tests MBR changes around allocation, deallocation
func TestBoxCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// increment for a size 24 box with 4 letter name
		proto := config.Consensus[cv]
		mbr := boxFee(proto, 28)

		appID := dl.fundedApp(addrs[0], proto.MinBalance+3*mbr, boxAppSource)

		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
		}

		adam := call.Args("create", "adam")
		dl.txn(adam, fmt.Sprintf("invalid Box reference %#x", "adam"))
		adam.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("adam")}}

		vb := dl.fullBlock(adam)

		// confirm the deltas has the creation
		require.Len(t, vb.Delta().KvMods, 1)
		for _, kvDelta := range vb.Delta().KvMods { // There's only one
			require.Nil(t, kvDelta.OldData) // A creation has nil OldData
			require.Len(t, kvDelta.Data, 24)
		}

		dl.txn(adam.Args("check", "adam", "\x00\x00"))
		dl.txgroup("box_create; assert", adam.Noted("one"), adam.Noted("two"))

		bobo := call.Args("create", "bobo")
		dl.txn(bobo, fmt.Sprintf("invalid Box reference %#x", "bobo"))
		bobo.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("bobo")}}
		dl.txn(bobo)
		dl.txgroup("box_create; assert", bobo.Noted("one"), bobo.Noted("two"))

		dl.beginBlock()
		chaz := call.Args("create", "chaz")
		chaz.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("chaz")}}
		dl.txn(chaz)
		dl.txn(chaz.Noted("again"), "box_create; assert")
		dl.endBlock()

		// new block
		dl.txn(chaz.Noted("again"), "box_create; assert")
		dogg := call.Args("create", "dogg")
		dogg.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("dogg")}}
		dl.txn(dogg, "below min")
		dl.txn(chaz.Args("delete", "chaz"))
		dl.txn(chaz.Args("delete", "chaz").Noted("again"), "box_del; assert")
		dl.txn(dogg)
		dl.txn(bobo.Args("delete", "bobo"))

		// empty name is illegal
		empty := call.Args("create", "")
		dl.txn(empty, "box names may not be zero")
		// and, of course, that's true even if there's a box ref with the empty name
		empty.Boxes = []transactions.BoxRef{{}}
		dl.txn(empty, "box names may not be zero")
	})
}

// TestBoxRecreate tests behavior when box_create is called for a box that already exists
func TestBoxRecreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// increment for a size 4 box with 4 letter name
		proto := config.Consensus[cv]
		mbr := boxFee(proto, 8)

		appID := dl.fundedApp(addrs[0], proto.MinBalance+mbr, boxAppSource)

		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("adam")}},
		}

		create := call.Args("create", "adam", "\x04") // box value size is 4 bytes
		recreate := call.Args("recreate", "adam", "\x04")

		dl.txn(recreate, "box_create; !; assert")
		dl.txn(create)
		dl.txn(recreate)
		dl.txn(call.Args("set", "adam", "\x01\x02\x03\x04"))
		dl.txn(call.Args("check", "adam", "\x01\x02\x03\x04"))
		dl.txn(recreate.Noted("again"))
		// a recreate does not change the value
		dl.txn(call.Args("check", "adam", "\x01\x02\x03\x04").Noted("after recreate"))
		// recreating with a smaller size fails
		dl.txn(call.Args("recreate", "adam", "\x03"), "box size mismatch 4 3")
		// recreating with a larger size fails
		dl.txn(call.Args("recreate", "adam", "\x05"), "box size mismatch 4 5")
		dl.txn(call.Args("check", "adam", "\x01\x02\x03\x04").Noted("after failed recreates"))

		// delete and actually create again
		dl.txn(call.Args("delete", "adam"))
		dl.txn(call.Args("create", "adam", "\x03"))

		dl.txn(call.Args("set", "adam", "\x03\x02\x01"))
		dl.txn(call.Args("check", "adam", "\x03\x02\x01"))
		dl.txn(recreate.Noted("after delete"), "box size mismatch 3 4")
		dl.txn(call.Args("recreate", "adam", "\x03"))
		dl.txn(call.Args("check", "adam", "\x03\x02\x01").Noted("after delete and recreate"))
	})
}

func TestBoxCreateAvailability(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		accessInCreate := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: 0, // This is an app-creation
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("hello")}},
			ApprovalProgram: `
              byte "hello"
              int 10
              box_create
`,
		}

		// We know box_create worked because this failure (checking the MBR)
		// happens at the end of the group evaluation.
		dl.txn(&accessInCreate, "balance 0 below min")

		// But let's fund it and be sure. This is "psychic". We're going to fund
		// the app address that we know the app will get. So this is a nice
		// test, but unrealistic way to actual create a box.
		psychic := basics.AppIndex(2)
		proto := config.Consensus[cv]
		if proto.AppForbidLowResources {
			psychic += 1000
		}

		dl.txn(&txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: psychic.Address(),
			Amount:   proto.MinBalance + boxFee(proto, 15),
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
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("hello")}},
			// Note that main() wraps the program so it does not run at creation time.
			ApprovalProgram: main(`
              byte "hello"
              int 10
              box_create
              assert
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

		payset := dl.txgroup("", &accessWhenCalled, &call)

		// Make sure that we actually did it.
		require.Equal(t, "we did it", payset[1].ApplyData.EvalDelta.InnerTxns[1].EvalDelta.Logs[0])
	})
}

// TestBoxRW tests reading writing boxes in consecutive transactions
func TestBoxRW(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		t.Parallel()
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		var bufNewLogger bytes.Buffer
		log := logging.NewLogger()
		log.SetOutput(&bufNewLogger)

		appID := dl.fundedApp(addrs[0], 1_000_000, boxAppSource)
		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("x")}},
		}

		dl.txn(call.Args("create", "x", "\x10"))                // 16
		vb := dl.fullBlock(call.Args("set", "x", "ABCDEFGHIJ")) // 10 long
		// confirm the deltas has the change, including the old value
		require.Len(t, vb.Delta().KvMods, 1)
		for _, kvDelta := range vb.Delta().KvMods { // There's only one
			require.Equal(t, kvDelta.OldData,
				[]byte(strings.Repeat("\x00", 16)))
			require.Equal(t, kvDelta.Data,
				[]byte("ABCDEFGHIJ\x00\x00\x00\x00\x00\x00"))
		}

		dl.txn(call.Args("check", "x", "ABCDE"))
		dl.txn(call.Args("check", "x", "ABCDEFGHIJ"))
		dl.txn(call.Args("check", "x", "ABCDEFGHIJ\x00"))

		dl.txn(call.Args("delete", "x"))
		dl.txn(call.Args("check", "x", "ABC"), "no such box")
		dl.txn(call.Args("create", "x", "\x08"))
		dl.txn(call.Args("check", "x", "\x00")) // it was cleared
		dl.txn(call.Args("set", "x", "ABCDEFGHIJ"), "replacement end 10")
		dl.txn(call.Args("check", "x", "\x00")) // still clear
		dl.txn(call.Args("set", "x", "ABCDEFGH"))
		dl.txn(call.Args("check", "x", "ABCDEFGH\x00"), "extraction end 9")
		dl.txn(call.Args("check", "x", "ABCDEFGH"))
		dl.txn(call.Args("set", "x", "ABCDEFGHI"), "replacement end 9")

		// Advance more than 320 rounds, ensure box is still there
		for i := 0; i < 330; i++ {
			dl.fullBlock()
		}
		time.Sleep(5 * time.Second) // balancesFlushInterval, so commit happens
		dl.fullBlock(call.Args("check", "x", "ABCDEFGH"))
		time.Sleep(100 * time.Millisecond) // give commit time to run, and prune au caches
		dl.fullBlock(call.Args("check", "x", "ABCDEFGH"))

		dl.txn(call.Args("create", "yy"), fmt.Sprintf("invalid Box reference %#x", "yy"))
		withBr := call.Args("create", "yy")
		withBr.Boxes = append(withBr.Boxes, transactions.BoxRef{Index: 1, Name: []byte("yy")})
		require.Error(dl.t, withBr.Txn().WellFormed(transactions.SpecialAddresses{}, dl.generator.GenesisProto()))
		withBr.Boxes[1].Index = 0
		dl.txn(withBr)
	})
}

// TestBoxAccountData tests that an account's data changes when boxes are created
func TestBoxAccountData(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	uint64ToArgStr := func(i uint64) string {
		encoded := make([]byte, 8)
		binary.BigEndian.PutUint64(encoded, i)
		return string(encoded)
	}

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		proto := config.Consensus[cv]

		var bufNewLogger bytes.Buffer
		log := logging.NewLogger()
		log.SetOutput(&bufNewLogger)

		appID := dl.fundedApp(addrs[0], 1_000_000, boxAppSource)
		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("x")}, {Index: 0, Name: []byte("y")}},
		}

		verifyAppSrc := main(`
txn ApplicationArgs 0
btoi
txn Accounts 1
acct_params_get AcctMinBalance
assert
==
assert

txn ApplicationArgs 1
btoi
txn Accounts 1
acct_params_get AcctTotalBoxes
assert
==
assert

txn ApplicationArgs 2
btoi
txn Accounts 1
acct_params_get AcctTotalBoxBytes
assert
==
assert
`)
		verifyAppID := dl.fundedApp(addrs[0], 0, verifyAppSrc)
		verifyAppCall := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: verifyAppID,
			Accounts:      []basics.Address{appID.Address()},
		}

		// The app account has no box data initially
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance), "\x00", "\x00"))

		dl.txn(call.Args("create", "x", "\x10")) // 16

		// It gets updated when a new box is created
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance+proto.BoxFlatMinBalance+17*proto.BoxByteMinBalance), "\x01", "\x11"))

		dl.txn(call.Args("create", "y", "\x05"))

		// And again
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance+2*proto.BoxFlatMinBalance+23*proto.BoxByteMinBalance), "\x02", "\x17"))

		// Advance more than 320 rounds, ensure box is still there
		for i := 0; i < 330; i++ {
			dl.fullBlock()
		}
		time.Sleep(5 * time.Second) // balancesFlushInterval, so commit happens
		dl.fullBlock(call.Args("check", "x", string(make([]byte, 16))))
		time.Sleep(100 * time.Millisecond) // give commit time to run, and prune au caches
		dl.fullBlock(call.Args("check", "x", string(make([]byte, 16))))

		// Still the same after caches are flushed
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance+2*proto.BoxFlatMinBalance+23*proto.BoxByteMinBalance), "\x02", "\x17"))

		dl.txns(call.Args("delete", "x"), call.Args("delete", "y"))

		// Data gets removed after boxes are deleted
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance), "\x00", "\x00"))
	})
}

func TestBoxIOBudgets(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appID := dl.fundedApp(addrs[0], 0, boxAppSource)
		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("x")}},
		}
		if ver < boxQuotaBumpVersion {
			dl.txn(call.Args("create", "x", "\x10\x00"), // 4096
				"write budget (1024) exceeded")
			call.Boxes = append(call.Boxes, transactions.BoxRef{})
		}
		dl.txn(call.Args("create", "x", "\x10\x00"), // 4096
			"write budget (2048) exceeded")
		call.Boxes = append(call.Boxes, transactions.BoxRef{})
		if ver < boxQuotaBumpVersion {
			dl.txn(call.Args("create", "x", "\x10\x00"), // 4096
				"write budget (3072) exceeded")
			call.Boxes = append(call.Boxes, transactions.BoxRef{})
		}
		dl.txn(call.Args("create", "x", "\x10\x00"), // now there are enough box refs
			"below min") // big box would need more balance
		dl.txn(call.Args("create", "x", "\x10\x01"), // 4097
			"write budget (4096) exceeded")

		// Create 4,096 byte box
		proto := config.Consensus[cv]
		fundApp := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: appID.Address(),
			Amount:   proto.MinBalance + boxFee(proto, 4096+1), // remember key len!
		}
		create := call.Args("create", "x", "\x10\x00")

		// Slight detour - Prove insufficient funding fails creation.
		fundApp.Amount--
		dl.txgroup("below min", &fundApp, create)
		fundApp.Amount++

		// Confirm desired creation happens.
		dl.txgroup("", &fundApp, create)

		// Now that we've created a 4,096 byte box, test READ budget
		// It works at the start, because call still has enough brs.
		dl.txn(call.Args("check", "x", "\x00"))
		call.Boxes = call.Boxes[:len(call.Boxes)-1] // remove one ref
		dl.txn(call.Args("check", "x", "\x00"), "box read budget")

		// Give a budget over 32768, confirm failure anyway
		empties := [32]transactions.BoxRef{}
		// These tests skip WellFormed, so the huge Boxes is ok
		call.Boxes = append(call.Boxes, empties[:]...)
		dl.txn(call.Args("create", "x", "\x80\x01"), "box size too large") // 32769
	})
}

// TestBoxInners trys various box manipulations through inner transactions
func TestBoxInners(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// Advance the creatable counter, so we don't have very low app ids that
		// could be mistaken for indices into ForeignApps.
		dl.txn(&txntest.Txn{Type: "pay", Sender: addrs[0], Receiver: addrs[0]})
		dl.txn(&txntest.Txn{Type: "pay", Sender: addrs[0], Receiver: addrs[0]})
		dl.txn(&txntest.Txn{Type: "pay", Sender: addrs[0], Receiver: addrs[0]})
		dl.txn(&txntest.Txn{Type: "pay", Sender: addrs[0], Receiver: addrs[0]})

		boxID := dl.fundedApp(addrs[0], 4_000_000, boxAppSource)  // there are some big boxes made
		passID := dl.fundedApp(addrs[0], 120_000, passThruSource) // lowish, show it's not paying for boxes
		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: passID,
			ForeignApps:   []basics.AppIndex{boxID},
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("x")}},
		}
		// The current Boxes gives top-level access to "x", not the inner app
		dl.txn(call.Args("create", "x", "\x10"), // 8
			fmt.Sprintf("invalid Box reference %#x", 'x'))

		// This isn't right: Index should be index into ForeignApps
		call.Boxes = []transactions.BoxRef{{Index: uint64(boxID), Name: []byte("x")}}
		require.Error(t, call.Txn().WellFormed(transactions.SpecialAddresses{}, dl.generator.genesisProto))

		call.Boxes = []transactions.BoxRef{{Index: 1, Name: []byte("x")}}
		if ver < boxQuotaBumpVersion {
			dl.txn(call.Args("create", "x", "\x10\x00"), // 4096
				"write budget (1024) exceeded")
			dl.txn(call.Args("create", "x", "\x04\x00")) // 1024
			call.Boxes = append(call.Boxes, transactions.BoxRef{Index: 1, Name: []byte("y")})
			dl.txn(call.Args("create", "y", "\x08\x00")) // 2048
		} else {
			dl.txn(call.Args("create", "x", "\x10\x00"), // 4096
				"write budget (2048) exceeded")
			dl.txn(call.Args("create", "x", "\x08\x00")) // 2048
			call.Boxes = append(call.Boxes, transactions.BoxRef{Index: 1, Name: []byte("y")})
			dl.txn(call.Args("create", "y", "\x10\x00")) // 4096
		}

		require.Len(t, call.Boxes, 2)
		setX := call.Args("set", "x", "A")
		dl.txn(setX, "read budget") // Boxes has x and y, their combined length is too big
		setX.Boxes = []transactions.BoxRef{{Index: 1, Name: []byte("x")}}
		dl.txn(setX)

		setY := call.Args("set", "y", "B")
		dl.txn(setY, "read budget") // Boxes has x and y, their combined length is too big
		setY.Boxes = []transactions.BoxRef{{Index: 1, Name: []byte("y")}}
		dl.txn(setY, "read budget") // Y is bigger needs more than 1 br
		// We recommend "empty" br, but a duplicate is also ok
		setY.Boxes = append(setY.Boxes, transactions.BoxRef{Index: 1, Name: []byte("y")})
		dl.txn(setY) // len(y) = 2048, io budget is 2*1024 right now

		// non-existent box also works
		setY.Boxes = []transactions.BoxRef{{Index: 1, Name: []byte("y")}, {Index: 0, Name: []byte("nope")}}
		dl.txn(setY) // len(y) = 2048, io budget is 2*1024 right now

		// now show can read both boxes based on brs in tx1
		checkX := call.Args("check", "x", "A")
		checkX.Boxes = nil
		checkY := call.Args("check", "y", "B")
		require.Len(t, checkY.Boxes, 2)
		// can't see x and y because read budget is only 2*1024
		dl.txgroup("box read budget", checkX, checkY)
		checkY.Boxes = append(checkY.Boxes, transactions.BoxRef{})
		dl.txgroup("", checkX, checkY)

		require.Len(t, setY.Boxes, 2) // recall that setY has ("y", "nope") right now. no "x"
		dl.txgroup(fmt.Sprintf("invalid Box reference %#x", 'x'), checkX, setY)

		setY.Boxes = append(setY.Boxes, transactions.BoxRef{Index: 1, Name: []byte("x")})
		dl.txgroup("", checkX, setY)

		// Cleanup
		dl.txn(call.Args("del", "x"), "read budget")
		dl.txn(call.Args("del", "y"), "read budget")
		// surprising but correct: they work when combined, because both txns
		// have both box refs, so the read budget goes up.
		dl.txgroup("", call.Args("delete", "x"), call.Args("delete", "y"))

		// Try some get/put action
		dl.txn(call.Args("put", "x", "john doe"))
		tib := dl.txn(call.Args("get", "x"))
		// we are passing this thru to the underlying box app which logs the get
		require.Equal(t, "john doe", tib.ApplyData.EvalDelta.InnerTxns[0].EvalDelta.Logs[0])
		dl.txn(call.Args("check", "x", "john"))

		// bad change because of length
		dl.txn(call.Args("put", "x", "steve doe"), "box_put wrong size")
		tib = dl.txn(call.Args("get", "x"))
		require.Equal(t, "john doe", tib.ApplyData.EvalDelta.InnerTxns[0].EvalDelta.Logs[0])

		// good change
		dl.txn(call.Args("put", "x", "mark doe"))
		dl.txn(call.Args("check", "x", "mark d"))
	})
}

// Create the app with bytecode in txn.ApplicationArgs[0], pass my arg[1] as created arg[0]
var passThruCreator = main(`
  itxn_begin
  txn TypeEnum; itxn_field TypeEnum
  txn ApplicationArgs 0; itxn_field ApprovalProgram
  txn ApplicationArgs 0; itxn_field ClearStateProgram // need something, won't be used
  txn ApplicationArgs 1; itxn_field ApplicationArgs
  itxn_submit
`)

// TestNewAppBoxCreate exercised proto.EnableUnnamedBoxCreate
func TestNewAppBoxCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// We're going to create an app that will, during its own creation,
		// create a box.  That requires two tricks.

		// 1) Figure out the appID it will have and prefund it.  This _could_ be
		// done within the group itself - an early transaction deduces the
		// transaction counter, so it can know what the later create will be,
		// and compute it's app address.

		// 2) a) Use the the predicted appID to name the box ref.
		// or b) Use 0 as the app in the box ref, meaning "this app"
		// or c) EnableUnnamedBoxCreate will allow such a creation if there are empty box refs.

		// 2a is pretty much impossible in practice, we can only do it here
		// because our blockchain is "quiet" we know the upcoming appID.

		// 2b won't work for inner app creates, since the 0 appID gets replaced
		// with the _top-level_ app's ID.

		// 2c would allow newly created apps, even if inners, to create boxes.
		// It also has the nice property of not needing to know the box's
		// name. So it can be computed in app.  We don't need the name because
		// we can short-circuit the lookup - the box _must_ be empty.

		// boxCreate is an app that tries to make a box from its first argument, even during its own creation.
		boxCreate := "txn ApplicationArgs 0; int 24; box_create;" // Succeeds if the box is created and did not already exist

		// boxPut is an app that tries to make a box from its first argument, even during its own creation (but using box_put)
		boxPut := "txn ApplicationArgs 0; int 24; bzero; box_put; int 1;"

		for _, createSrc := range []string{boxCreate, boxPut} {
			// doubleSrc tries to create TWO boxes. The second is always named by ApplicationArgs 1
			doubleSrc := createSrc + `txn ApplicationArgs 1; int 24; box_create; pop;` // return result of FIRST box_create
			// need to call one inner txn, and have have mbr for itself and inner created app
			passID := dl.fundedApp(addrs[0], 201_000, passThruCreator) // Will be used to show inners have same power

			// Since we used fundedApp, the next app created would be passID+2.
			// We'll prefund a whole bunch of the next apps that we can then create
			// at will below.

			var testTxns = basics.AppIndex(20)
			for i := range testTxns {
				dl.txn(&txntest.Txn{Type: "pay", Sender: addrs[0], Receiver: (passID + 2 + testTxns + i).Address(), Amount: 500_000})
			}

			// Try to create it. It will fail because there's no box ref. (does not increment txncounter)
			dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
				ApprovalProgram: createSrc, ApplicationArgs: [][]byte{{0x01}}},
				"invalid Box reference 0x01")

			// 2a. Create it with a box ref of the predicted appID
			dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
				ApprovalProgram: createSrc, ApplicationArgs: [][]byte{{0x01}},
				ForeignApps: []basics.AppIndex{passID + testTxns + 2},
				Boxes:       []transactions.BoxRef{{Index: 1, Name: []byte{0x01}}}})

			// 2a. Create it with a box ref of the predicted appID (Access list)
			if ver >= accessVersion {
				dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
					ApprovalProgram: createSrc, ApplicationArgs: [][]byte{{0x01}},
					Access: []transactions.ResourceRef{
						{App: passID + testTxns + 3},
						{Box: transactions.BoxRef{Index: 1, Name: []byte{0x01}}}}})
			}

			// 2b. Create it with a box ref of 0, which means "this app"
			dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
				ApprovalProgram: createSrc, ApplicationArgs: [][]byte{{0x01}},
				Boxes: []transactions.BoxRef{{Index: 0, Name: []byte{0x01}}}})

			// 2b. Create it with a box ref of 0, which means "this app" (Access List)
			if ver >= accessVersion {
				dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
					ApprovalProgram: createSrc, ApplicationArgs: [][]byte{{0x01}},
					Access: []transactions.ResourceRef{
						{Box: transactions.BoxRef{Index: 0, Name: []byte{0x01}}}}})
			}

			// you can manipulate it twice if you want (this tries to create it twice)
			dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
				ApprovalProgram: doubleSrc, ApplicationArgs: [][]byte{{0x01}, {0x01}},
				Boxes: []transactions.BoxRef{{Index: 0, Name: []byte{0x01}}}})

			// but you still can't make a second box
			dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
				ApprovalProgram: doubleSrc, ApplicationArgs: [][]byte{{0x01}, {0x02}},
				Boxes: []transactions.BoxRef{{Index: 0, Name: []byte{0x01}}}},
				"invalid Box reference 0x02")

			// until you list it as well
			dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
				ApprovalProgram: doubleSrc, ApplicationArgs: [][]byte{{0x01}, {0x02}},
				Boxes: []transactions.BoxRef{
					{Index: 0, Name: []byte{0x01}},
					{Index: 0, Name: []byte{0x02}},
				}})

			if ver >= newAppCreateVersion {
				// 2c. Create it with an empty box ref
				dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
					ApprovalProgram: createSrc, ApplicationArgs: [][]byte{{0x01}},
					Boxes: []transactions.BoxRef{{}}})

				// 2c. Create it with an empty box ref
				dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
					ApprovalProgram: createSrc, ApplicationArgs: [][]byte{{0x01}},
					Access: []transactions.ResourceRef{{Box: transactions.BoxRef{}}}})

				// but you can't do a second create
				dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
					ApprovalProgram: doubleSrc, ApplicationArgs: [][]byte{{0x01}, {0x02}},
					Boxes: []transactions.BoxRef{{}}},
					"invalid Box reference 0x02")

				// until you add a second box ref
				dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
					ApprovalProgram: doubleSrc, ApplicationArgs: [][]byte{{0x01}, {0x02}},
					Boxes: []transactions.BoxRef{{}, {}}})

				// Now confirm that 2c also works for an inner created app
				ops, err := logic.AssembleString("#pragma version 12\n" + createSrc)
				require.NoError(t, err, ops.Errors)
				createSrcByteCode := ops.Program
				// create app as an inner, fails w/o empty box ref
				dl.txn(&txntest.Txn{Sender: addrs[0],
					Type:            "appl",
					ApplicationID:   passID,
					ApplicationArgs: [][]byte{createSrcByteCode, {0x01}},
				}, "invalid Box reference 0x01")
				// create app as an inner, succeeds w/ empty box ref
				dl.txn(&txntest.Txn{Sender: addrs[0],
					Type:            "appl",
					ApplicationID:   passID,
					ApplicationArgs: [][]byte{createSrcByteCode, {0x01}},
					Boxes:           []transactions.BoxRef{{}},
				})
			} else {
				// 2c. Doesn't work yet until `newAppCreateVersion`
				dl.txn(&txntest.Txn{Type: "appl", Sender: addrs[0],
					ApprovalProgram: createSrc, ApplicationArgs: [][]byte{{0x01}},
					Boxes: []transactions.BoxRef{{}}},
					"invalid Box reference 0x01")
			}
		}
	})
}
