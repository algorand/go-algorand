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

	ledger.NewApp(txn.Sender, 888, basics.AppParams{})
	logic.TestApp(t, `byte "self"; int 24; box_create`, ep)
	ledger.DeleteBox(888, "self")
	logic.TestApp(t, `byte "self"; int 24; box_create`, ep)
	ledger.DeleteBox(888, "self")
	logic.TestApp(t, `byte "self"; int 24; box_create; assert; byte "self"; int 24; box_create; !`, ep)
	ledger.DeleteBox(888, "self")
	logic.TestApp(t, `byte "self"; int 24; box_create; assert; byte "other"; int 24; box_create`, ep)
	ledger.DeleteBox(888, "self")

	logic.TestApp(t, `byte "self"; int 24; box_create; assert; byte "self"; box_del`, ep)
	logic.TestApp(t, `byte "self"; box_del; !`, ep)
	logic.TestApp(t, `byte "self"; int 24; box_create; assert
                     byte "self"; box_del; assert
                     byte "self"; box_del; !`, ep)
}

func TestBoxNewBad(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()

	ledger.NewApp(txn.Sender, 888, basics.AppParams{})
	logic.TestApp(t, `byte "self"; int 999; box_create`, ep, "write budget")
	ledger.DeleteBox(888, "self")

	// In test proto, you get 100 I/O budget per boxref
	ten := [10]transactions.BoxRef{}
	txn.Boxes = append(txn.Boxes, ten[:]...) // write budget is now 11*100 = 1100
	logic.TestApp(t, `byte "self"; int 999; box_create`, ep)
	ledger.DeleteBox(888, "self")
	logic.TestApp(t, `byte "self"; int 1000; box_create`, ep)
	ledger.DeleteBox(888, "self")
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
	ledger.DeleteBox(888, "self")
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
	}, nil, 7, ledger)
	// after creation, modification, the third can read it
	logic.TestApps(t, []string{
		`byte "self"; int 64; box_create`,
		`byte "self"; int 2; byte "hi"; box_replace; int 1`,
		`byte "self"; int 1; int 4; box_extract; byte 0x00686900; ==`, // "\0hi\0"
	}, nil, 7, ledger)
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
	}, nil, 7, ledger, logic.NewExpect(1, "invalid Box reference B"))

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
	}, group, 7, ledger, logic.NewExpect(1, "no such box"))

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
	}, group, 7, ledger, logic.NewExpect(1, "no such box"))

}

func TestBoxReadBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ledger := logic.NewLedger(nil)
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})
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
	ledger.DeleteBox(888, "self") // cleanup (doing it in a program would fail b/c the 201 len box exists)

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
	ledger.DeleteBox(888, "other")

	logic.TestApp(t, `byte "self"; box_del; assert
                      byte "self"; int 6; box_create; assert
                      byte "other"; int 196; box_create; assert
                      byte "self"; box_del;`, ep) // deletion means we don't pay for write bytes

	logic.TestApp(t, `byte "other"; box_del`, ep) // cleanup (self was already deleted in last test)
	logic.TestApp(t, `byte "other"; box_del; !`, ep)
	logic.TestApp(t, `byte "junk"; box_del`, ep, "invalid Box reference")

	// Create two boxes, that sum to over budget, then test trying to use them together
	logic.TestApp(t, `byte "self"; int 101; box_create`, ep)
	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "other"; int 101; box_create`, ep, "write budget (200) exceeded")
	// error was detected, but the TestLedger now has both boxes present
	logic.TestApp(t, `byte "self"; int 1; byte 0x3333; box_replace;
                      byte "other"; int 1; byte 0x3333; box_replace;
                      int 1`, ep, "read budget (200) exceeded")
	ledger.DeleteBox(888, "other")
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
	ledger.DeleteBox(888, "self")

	// put and get can interact with created boxes
	logic.TestApp(t, `byte "self"; int 3; box_create`, ep)
	logic.TestApp(t, `byte "self"; box_get; assert; byte 0x000000; ==`, ep)
	logic.TestApp(t, `byte "self"; byte 0xAABBCC; box_put; int 1`, ep)
	logic.TestApp(t, `byte "self"; int 1; byte 0xDDEE; box_replace; int 1`, ep)
	logic.TestApp(t, `byte "self"; box_get; assert; byte 0xAADDEE; ==`, ep)
	ledger.DeleteBox(888, "self")

	// box_get panics if the box is too big
	ep.Proto.MaxBoxSize = 5000
	ep.Proto.BytesPerBoxReference = 5000 // avoid write budget error
	logic.TestApp(t, `byte "self"; int 4098; box_create; assert; // bigger than maxStringSize
                      byte "self"; box_get; assert; len`, ep,
		"box_get produced a too big")

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
