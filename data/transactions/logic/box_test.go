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

package logic_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestBoxNewDel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()

	for _, size := range []int{24, 0} {
		t.Run(fmt.Sprintf("box size=%d", size), func(t *testing.T) {
			createSelf := fmt.Sprintf(`byte "self"; int %d; box_create;`, size)
			createOther := fmt.Sprintf(`byte "other"; int %d; box_create;`, size)

			ledger.NewApp(txn.Sender, 888, basics.AppParams{})

			logic.TestApp(t, createSelf, ep)
			ledger.DelBoxes(888, "self")

			logic.TestApp(t, createSelf+`assert;`+createSelf+`!`, ep)
			ledger.DelBoxes(888, "self")
			logic.TestApp(t, createSelf+`assert;`+createOther, ep)
			ledger.DelBoxes(888, "self")

			logic.TestApp(t, createSelf+`assert; byte "self"; box_del`, ep)
			logic.TestApp(t, `byte "self"; box_del; !`, ep)
			logic.TestApp(t, createSelf+`assert
                                        byte "self"; box_del; assert
                                        byte "self"; box_del; !`, ep)
			ledger.DelBoxes(888, "self")

			logic.TestApp(t, fmt.Sprintf(
				`byte "self"; box_get; !; assert; pop
                 byte "self"; int %d; bzero; box_put; int 1`, size), ep)
		})
	}

}

func TestBoxNewBad(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()

	ledger.NewApp(txn.Sender, 888, basics.AppParams{})
	logic.TestApp(t, `byte "self"; int 999; box_create`, ep, "write budget")

	// In test proto, you get 100 I/O budget per boxref
	ten := [10]transactions.BoxRef{}
	txn.Boxes = append(txn.Boxes, ten[:]...) // write budget is now 11*100 = 1100
	logic.TestApp(t, `byte "self"; int 999; box_create`, ep)
	ledger.DelBoxes(888, "self")
	logic.TestApp(t, `byte "self"; int 1000; box_create`, ep)
	ledger.DelBoxes(888, "self")
	logic.TestApp(t, `byte "self"; int 1001; box_create`, ep, "box size too large")

	logic.TestApp(t, `byte "unknown"; int 1000; box_create`, ep, "invalid Box reference")

	long := strings.Repeat("x", 65)
	txn.Boxes = []transactions.BoxRef{{Name: []byte(long)}}
	logic.TestApp(t, fmt.Sprintf(`byte "%s"; int 1000; box_create`, long), ep, "name too long")

	txn.Boxes = []transactions.BoxRef{{Name: []byte("")}} // irrelevant, zero check comes first anyway
	logic.TestApp(t, `byte ""; int 1000; box_create`, ep, "zero length")
}

func TestBoxReadWrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()

	ledger.NewApp(txn.Sender, 888, basics.AppParams{})
	// extract some bytes until past the end, confirm the begin as zeros, and
	// when it fails.
	logic.TestApp(t, `byte "self"; int 4; box_create; assert
                byte "self"; int 1; int 2; box_extract;
                byte 0x0000; ==; assert;
                byte "self"; int 1; int 3; box_extract;
                byte 0x000000; ==; assert;
                byte "self"; int 0; int 4; box_extract;
                byte 0x00000000; ==; assert;
                int 1`, ep)

	logic.TestApp(t, `byte "self"; int 1; int 4; box_extract;
                byte 0x00000000; ==`, ep, "extraction end 5")

	// Replace some bytes until past the end, confirm when it fails.
	logic.TestApp(t, `byte "self"; int 1; byte 0x3031; box_replace;
                      byte "self"; int 0; int 4; box_extract;
                      byte 0x00303100; ==`, ep)
	logic.TestApp(t, `byte "self"; int 1; byte 0x303132; box_replace;
                      byte "self"; int 0; int 4; box_extract;
                      byte 0x00303132; ==`, ep)
	logic.TestApp(t, `byte "self"; int 1; byte 0x30313233; box_replace;
                      byte "self"; int 0; int 4; box_extract;
                      byte 0x0030313233; ==`, ep, "replacement end 5")

	// Replace with different byte in different place.
	logic.TestApp(t, `byte "self"; int 0; byte 0x4444; box_replace;
                      byte "self"; int 0; int 4; box_extract;
                      byte 0x44443132; ==`, ep)

	// All bow down to the God of code coverage!
	ledger.DelBoxes(888, "self")
	logic.TestApp(t, `byte "self"; int 1; byte 0x3031; box_replace`, ep,
		"no such box")
	logic.TestApp(t, `byte "junk"; int 1; byte 0x3031; box_replace`, ep,
		"invalid Box reference")
}

func TestBoxAcrossTxns(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ledger := logic.NewLedger(nil)
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})
	// After creation in first txn, second one can read it (though it's empty)
	logic.TestApps(t, []string{
		`byte "self"; int 64; box_create`,
		`byte "self"; int 10; int 4; box_extract; byte 0x00000000; ==`,
	}, nil, 8, ledger)
	// after creation, modification, the third can read it
	logic.TestApps(t, []string{
		`byte "self"; int 64; box_create`,
		`byte "self"; int 2; byte "hi"; box_replace; int 1`,
		`byte "self"; int 1; int 4; box_extract; byte 0x00686900; ==`, // "\0hi\0"
	}, nil, 8, ledger)
}

// TestDirtyTracking gives confidence that the number of dirty bytes to be
// written is tracked properly, despite repeated creates/deletes of the same
// thing, touches in different txns, etc.
func TestDirtyTracking(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()

	ledger.NewApp(txn.Sender, 888, basics.AppParams{})
	logic.TestApp(t, `byte "self"; int 200; box_create`, ep)
	logic.TestApp(t, `byte "other"; int 201; box_create`, ep, "write budget")
	// deleting "self" doesn't give extra write budget to create big "other"
	logic.TestApp(t, `byte "self"; box_del; !; byte "other"; int 201; box_create`, ep,
		"write budget")

	// though it cancels out a creation that happened here
	logic.TestApp(t, `byte "self"; int 200; box_create; assert
                      byte "self"; box_del; assert
                      byte "self"; int 200; box_create;
                     `, ep)

	ledger.DelBoxes(888, "self", "other")
	// same, but create a different box than deleted
	logic.TestApp(t, `byte "self"; int 200; box_create; assert
                      byte "self"; box_del; assert
                      byte "other"; int 200; box_create;
                     `, ep)

	// no funny business by trying to del twice!  this case is also interested
	// because the read budget is spent on "other", which is 200, while the
	// write budget is spent on "self"
	logic.TestApp(t, `byte "other"; box_len; assert`, ep) // reminder, "other" exists!
	logic.TestApp(t, `byte "self"; int 200; box_create; assert
                      byte "self"; box_del; assert
                      byte "self"; box_del; !; assert
                      byte "self"; int 201; box_create;
                     `, ep, "write budget")
	logic.TestApp(t, `byte "self"; box_len; !; assert; !`, ep) // "self" was not made
	logic.TestApp(t, `byte "self"; int 200; box_create`, ep)   // make it
	// Now that both exist with size 200, naming both in Boxes causes failure
	logic.TestApp(t, `int 1`, ep, "read budget")

}

func TestBoxUnavailableWithClearState(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := map[string]string{
		"box_create":  `byte "self"; int 64; box_create`,
		"box_del":     `byte "self"; box_del`,
		"box_extract": `byte "self"; int 7; int 0; box_extract`,
		"box_get":     `byte "self"; box_get`,
		"box_len":     `byte "self"; box_len`,
		"box_put":     `byte "put"; byte "self"; box_put`,
		"box_replace": `byte "self"; int 0; byte "new"; box_replace`,
	}

	for name, program := range tests {
		t.Run(name, func(t *testing.T) {
			ep, _, l := logic.MakeSampleEnv()
			l.NewApp(basics.Address{}, 888, basics.AppParams{})
			ep.TxnGroup[0].Txn.OnCompletion = transactions.ClearStateOC
			logic.TestApp(t, program, ep, "boxes may not be accessed from ClearState program")
		})
	}
}

func TestBoxAvailability(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ledger := logic.NewLedger(nil)
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})

	// B is not available (recall that "self" is set up by MakeSampleEnv, in TestApps)
	logic.TestApps(t, []string{
		`byte "self"; int 64; box_create`,
		`byte "B"; int 10; int 4; box_extract; byte 0x00000000; ==`,
	}, nil, 8, ledger, logic.NewExpect(1, "invalid Box reference B"))

	// B is available if indexed by 0 in tx[1].Boxes
	group := logic.MakeSampleTxnGroup(logic.MakeSampleTxn(), txntest.Txn{
		Type:          "appl",
		ApplicationID: 10000,
		Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("B")}},
	}.SignedTxn())
	group[0].Txn.Type = protocol.ApplicationCallTx
	logic.TestApps(t, []string{
		`byte "self"; int 64; box_create`,
		`byte "B"; int 10; int 4; box_extract; byte 0x00000000; ==`,
	}, group, 8, ledger, logic.NewExpect(1, "no such box"))

	// B is available if listed by appId in tx[1].Boxes
	group = logic.MakeSampleTxnGroup(logic.MakeSampleTxn(), txntest.Txn{
		Type:          "appl",
		ApplicationID: 10000,
		ForeignApps:   []basics.AppIndex{10000},
		Boxes:         []transactions.BoxRef{{Index: 1, Name: []byte("B")}},
	}.SignedTxn())
	group[0].Txn.Type = protocol.ApplicationCallTx
	logic.TestApps(t, []string{
		`byte "self"; int 64; box_create`,
		`byte "B"; int 10; int 4; box_extract; byte 0x00000000; ==`,
	}, group, 8, ledger, logic.NewExpect(1, "no such box"))
}

func TestBoxReadBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	appID := basics.AppIndex(888)
	appAddr := appID.Address()

	ep, txn, ledger := logic.MakeSampleEnv()
	ledger.NewApp(basics.Address{}, appID, basics.AppParams{})

	// Sample txn has two box refs, so read budget is 2*100

	ledger.NewBox(appID, "self", make([]byte, 100), appAddr)
	ledger.NewBox(appID, "other", make([]byte, 100), appAddr)
	ledger.NewBox(appID, "third", make([]byte, 100), appAddr)

	// Right at budget
	logic.TestApp(t, `byte "self"; box_len; assert; byte "other"; box_len; assert; ==`, ep)

	// With three box refs, read budget is now 3*100
	txn.Boxes = append(txn.Boxes, transactions.BoxRef{Name: []byte("third")})
	logic.TestApp(t, `byte "self"; box_len; assert; byte "third"; box_len; assert; ==`, ep)

	// Increase "third" box size to 101
	ledger.DelBox(appID, "third", appAddr)
	ledger.NewBox(appID, "third", make([]byte, 101), appAddr)

	// Budget exceeded
	logic.TestApp(t, `byte "self"; box_len; assert; byte "third"; box_len; assert; ==`, ep, "box read budget (300) exceeded")
	// Still exceeded if we don't touch the boxes
	logic.TestApp(t, `int 1`, ep, "box read budget (300) exceeded")

	// Still exceeded with one box ref
	txn.Boxes = txn.Boxes[2:]
	logic.TestApp(t, `byte "third"; box_len; assert; int 101; ==`, ep, "box read budget (100) exceeded")

	// But not with two
	txn.Boxes = append(txn.Boxes, transactions.BoxRef{})
	logic.TestApp(t, `byte "third"; box_len; assert; int 101; ==`, ep)
}

func TestBoxWriteBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, _, ledger := logic.MakeSampleEnv()
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})

	// Sample tx[0] has two box refs, so write budget is 2*100

	// Test simple use of one box, less than, equal, or over budget
	logic.TestApp(t, `byte "self"; int 4; box_create`, ep)
	logic.TestApp(t, `byte "self"; box_del; assert
                      byte "self"; int 199; box_create`, ep)
	logic.TestApp(t, `byte "self"; box_del; assert
                      byte "self"; int 200; box_create`, ep)
	logic.TestApp(t, `byte "self"; box_del; assert
                      byte "self"; int 201; box_create`, ep, "write budget (200) exceeded")

	// Test interplay of two different boxes being created
	logic.TestApp(t, `byte "self"; int 4; box_create; assert
                      byte "other"; int 4; box_create`, ep)

	logic.TestApp(t, `byte "self"; box_del; assert; byte "other"; box_del; assert
                      byte "self"; int 4; box_create; assert;
                      byte "other"; int 196; box_create`, ep)

	logic.TestApp(t, `byte "self"; box_del; assert; byte "other"; box_del; assert
                      byte "self"; int 6; box_create; assert
                      byte "other"; int 196; box_create`, ep,
		"write budget (200) exceeded")
	ledger.DelBoxes(888, "other")

	logic.TestApp(t, `byte "self"; box_del; assert
                      byte "self"; int 6; box_create; assert
                      byte "other"; int 196; box_create; assert // fails to create
                      byte "self"; box_del;`, ep, "write budget (200) exceeded")

	logic.TestApp(t, `byte "other"; int 196; box_create`, ep)
	logic.TestApp(t, `byte "self"; box_del`, ep, "read budget") // 6 + 196 > 200
	logic.TestApp(t, `byte "junk"; box_del`, ep, "read budget") // fails before invalid "junk" is noticed
	ledger.DelBoxes(888, "self", "other")
	logic.TestApp(t, `byte "junk"; box_del`, ep, "invalid Box reference")

	// Create two boxes, that sum to over budget, then test trying to use them together
	logic.TestApp(t, `byte "self"; int 101; box_create`, ep)
	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "other"; int 101; box_create`, ep, "write budget (200) exceeded")

	logic.TestApp(t, `byte "other"; int 101; box_create`, ep)
	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "other"; int 1; byte 0x3333; box_replace;
                      int 1`, ep, "read budget (200) exceeded")
	ledger.DelBoxes(888, "other")

	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "other"; int 10; box_create`, ep)
	// They're now small enough to read and write
	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "other"; int 1; byte 0x3333; box_replace;
                      int 1`, ep)
	// writing twice is no problem (even though it's the big one)
	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "self"; int 50; byte 0x3333; box_replace;
                      byte "other"; int 1; byte 0x3333; box_replace;
                      int 1`, ep)

	logic.TestApp(t, `byte "self"; box_del; assert; byte "other"; box_del`, ep) // cleanup

}

// TestWriteBudgetPut ensures we get write budget right for box_put
func TestWriteBudgetPut(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, _, ledger := logic.MakeSampleEnv()
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})

	// Sample tx[0] has two box refs, so write budget is 2*100

	// Test simple use of one box
	logic.TestApp(t, `byte "self"; int 200; box_create`, ep) // equal to budget
	logic.TestApp(t, `byte "self"; box_del`, ep)
	logic.TestApp(t, `byte "self"; int 201; box_create`, ep, // 1 over budget
		"write budget")

	// More complicated versions that use 1 or more 150 byte boxes, so one is ok, two is over
	logic.TestApp(t, `byte "self"; int 150; box_create`, ep)
	logic.TestApp(t, `byte "self"; int 150; bzero; box_put; int 1`, ep)
	logic.TestApp(t, `byte "self"; int 149; bzero; byte "x"; concat; box_put; int 1`, ep)
	// puts to same name, doesn't go over budget (although we don't optimize
	// away puts with the same content, this test uses different contents just
	// to be sure).
	logic.TestApp(t, `byte "self"; int 150; bzero; box_put;
	                  byte "self"; int 149; bzero; byte "x"; concat; box_put; int 1`, ep)
	// puts to different names do
	logic.TestApp(t, `byte "self"; int 150; bzero; box_put;
	                  byte "other"; int 149; bzero; byte "x"; concat; box_put; int 1`, ep,
		"write budget")

	// testing a regression: ensure box_put does not double debit when creating
	logic.TestApp(t, `byte "self"; int 150; bzero; box_put; int 1`, ep)
}

// TestBoxRepeatedCreate ensures that app is not charged write budget for
// creates that don't do anything.
func TestBoxRepeatedCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, _, ledger := logic.MakeSampleEnv()
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})

	// Sample tx[0] has two box refs, so write budget is 2*100
	logic.TestApp(t, `byte "self"; int 201; box_create`, ep,
		"write budget")
	logic.TestApp(t, `byte "self"; int 200; box_create`, ep)
	logic.TestApp(t, `byte "self"; int 200; box_create; !; assert // does not actually create
                      byte "other"; int 200; box_create; assert // does create, and budget should be enough
                      int 1`, ep)

	ledger.DelBoxes(888, "self", "other")
	logic.TestApp(t, `byte "other"; int 200; box_create; assert
                      byte "other"; box_del; assert
                      byte "other"; int 200; box_create`, ep)

}

func TestIOBudgetGrow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})
	ledger.CreateBox(888, "self", 101)
	ledger.CreateBox(888, "other", 101)

	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "other"; int 1; byte 0x3333; box_replace;
                      int 1`, ep, "read budget (200) exceeded")

	txn.Boxes = append(txn.Boxes, transactions.BoxRef{})
	// Since we added an empty BoxRef, we can read > 200.
	logic.TestApp(t, `byte "self"; int 1; int 7; box_extract; pop;
                      byte "other"; int 1; int 7; box_extract; pop;
                      int 1`, ep)
	// Add write, for that matter
	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "other"; int 1; byte 0x3333; box_replace;
                      int 1`, ep)

	txn.Boxes = append(txn.Boxes, transactions.BoxRef{Name: []byte("another")})

	// Here we read 202, and write a very different 350 (since we now have 4 brs)
	logic.TestApp(t, `byte "self"; int 1; int 7; box_extract; pop;
                      byte "other"; int 1; int 7; box_extract; pop;
                      byte "another"; int 350; box_create`, ep)
}

func TestConveniences(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, _, ledger := logic.MakeSampleEnv()
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})

	// box_get of a new name reports !exists, and returns 0 length bytes.
	logic.TestApp(t, `byte "self"; box_get; !; assert; len; !`, ep)

	// box_len of a new name reports !exists, and returns 0 as the length
	logic.TestApp(t, `byte "self"; box_len; !; assert; !`, ep)

	// box_put creates the box with contents provided
	logic.TestApp(t, `byte "self"; byte 0x3132; box_put;
                     byte "self"; box_len; assert; int 2; ==; assert
                     byte "self"; box_get; assert; byte 0x3132; ==`, ep)

	// box_put fails if box exists and is wrong size (self exists from last test)
	logic.TestApp(t, `byte "self"; byte 0x313233; box_put; int 1`, ep,
		"box_put wrong size")
	ledger.DelBoxes(888, "self")

	// put and get can interact with created boxes
	logic.TestApp(t, `byte "self"; int 3; box_create`, ep)
	logic.TestApp(t, `byte "self"; box_get; assert; byte 0x000000; ==`, ep)
	logic.TestApp(t, `byte "self"; byte 0xAABBCC; box_put; int 1`, ep)
	logic.TestApp(t, `byte "self"; int 1; byte 0xDDEE; box_replace; int 1`, ep)
	logic.TestApp(t, `byte "self"; box_get; assert; byte 0xAADDEE; ==`, ep)
	ledger.DelBoxes(888, "self")

	// box_get panics if the box is too big (for TEAL, or for proto)
	ep.Proto.MaxBoxSize = 5000
	ep.Proto.BytesPerBoxReference = 5000 // avoid write budget error
	logic.TestApp(t, `byte "self"; int 4098; box_create; assert; // bigger than maxStringSize
                      byte "self"; box_get; assert; len`, ep,
		"box_get produced a too big")
}

// TestEarlyPanics ensures that all of the box opcodes die early if they are
// given an empty or too long name.
func TestEarlyPanics(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := map[string]string{
		"box_create":  `byte "%s"; int 10; box_create`,
		"box_del":     `byte "%s"; box_del`,
		"box_extract": `byte "%s"; int 1; int 2; box_extract`,
		"box_get":     `byte "%s"; box_get`,
		"box_len":     `byte "%s"; box_len`,
		"box_put":     `byte "%s"; byte "hello"; box_put`,
		"box_replace": `byte "%s"; int 0; byte "new"; box_replace`,
	}

	ep, _, l := logic.MakeSampleEnv()
	l.NewApp(basics.Address{}, 888, basics.AppParams{})

	for name, program := range tests {
		t.Run(name+"/zero", func(t *testing.T) {
			logic.TestApp(t, fmt.Sprintf(program, ""), ep, "zero length")
		})
	}

	big := strings.Repeat("x", 65)
	for name, program := range tests {
		t.Run(name+"/long", func(t *testing.T) {
			logic.TestApp(t, fmt.Sprintf(program, big), ep, "name too long")
		})
	}

}

func TestBoxTotals(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()

	ledger.NewApp(txn.Sender, 888, basics.AppParams{})
	// The SENDER certainly has no boxes (but does exist)
	logic.TestApp(t, `int 0; acct_params_get AcctTotalBoxes; pop; !`, ep)
	// Nor does the app account, to start
	logic.TestApp(t, `int 888; app_params_get AppAddress; assert;
	                  acct_params_get AcctTotalBoxes; pop; !; `, ep)
	// Create a 31 byte box with a 4 byte name
	logic.TestApp(t, `byte "self"; int 31; box_create`, ep)
	logic.TestApp(t, `int 888; app_params_get AppAddress; assert;
	                  acct_params_get AcctTotalBoxes; pop; int 1; ==`, ep)
	logic.TestApp(t, `int 888; app_params_get AppAddress; assert;
	                  acct_params_get AcctTotalBoxBytes; pop; int 35; ==`, ep)
}

func TestMakeBoxKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type testCase struct {
		description string
		name        string
		app         basics.AppIndex
		key         string
		err         string
	}

	pp := func(tc testCase) string {
		return fmt.Sprintf("<<<%s>>> (name, app) = (%#v, %d) --should--> key = %#v (err = [%s])", tc.description, tc.name, tc.app, tc.key, tc.err)
	}

	var testCases = []testCase{
		// COPACETIC:
		{"zero appid", "stranger", 0, "bx:\x00\x00\x00\x00\x00\x00\x00\x00stranger", ""},
		{"typical", "348-8uj", 131231, "bx:\x00\x00\x00\x00\x00\x02\x00\x9f348-8uj", ""},
		{"empty box name", "", 42, "bx:\x00\x00\x00\x00\x00\x00\x00*", ""},
		{"random byteslice", "{\xbb\x04\a\xd1\xe2\xc6I\x81{", 13475904583033571713, "bx:\xbb\x04\a\xd1\xe2\xc6I\x81{\xbb\x04\a\xd1\xe2\xc6I\x81{", ""},

		// ERRORS:
		{"too short", "", 0, "stranger", "SplitBoxKey() cannot extract AppIndex as key (stranger) too short (length=8)"},
		{"wrong prefix", "", 0, "strangersINTHEdark", "SplitBoxKey() illegal app box prefix in key (strangersINTHEdark). Expected prefix 'bx:'"},
	}

	for _, tc := range testCases {
		app, name, err := logic.SplitBoxKey(tc.key)

		if tc.err == "" {
			key := logic.MakeBoxKey(tc.app, tc.name)
			require.Equal(t, tc.app, app, pp(tc))
			require.Equal(t, tc.name, name, pp(tc))
			require.Equal(t, tc.key, key, pp(tc))
		} else {
			require.EqualError(t, err, tc.err, pp(tc))
		}
	}
}
