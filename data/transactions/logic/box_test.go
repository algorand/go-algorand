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
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBoxNewDel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()

	ledger.NewApp(txn.Sender, 888, basics.AppParams{})
	logic.TestApp(t, "int 24; byte 0x11; box_create; int 1", ep)
	logic.TestApp(t, "int 24; byte 0x12; box_create; int 24; byte 0x12; box_create; int 1", ep,
		"already exists")
	logic.TestApp(t, "int 24; byte 0x13; box_create; int 24; byte 0x14; box_create; int 1", ep)

	logic.TestApp(t, "int 24; byte 0x15; box_create; byte 0x15; box_del; int 1", ep)
	logic.TestApp(t, "int 24; byte 0x17; box_del; int 1", ep, "no such box")
	logic.TestApp(t, "int 24; byte 0x18; box_create; byte 0x18; box_del; byte 0x18; box_del; int 1", ep,
		"no such box")
}

func TestBoxReadWrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, txn, ledger := logic.MakeSampleEnv()

	ledger.NewApp(txn.Sender, 888, basics.AppParams{})
	// extract some bytes until past the end, confirm the begin as zeros, and
	// when it fails.
	logic.TestApp(t, `int 4; byte 0x11; box_create;
                byte 0x11; int 1; int 2; box_extract;
                byte 0x0000; ==`, ep)
	logic.TestApp(t, `int 4; byte 0x12; box_create;
                byte 0x12; int 1; int 3; box_extract;
                byte 0x000000; ==`, ep)
	logic.TestApp(t, `int 4; byte 0x13; box_create;
                byte 0x13; int 1; int 4; box_extract;
                byte 0x00000000; ==`, ep, "extract range")
	logic.TestApp(t, `int 4; byte 0x14; box_create;
                byte 0x14; int 0; int 4; box_extract;
                byte 0x00000000; ==`, ep)

	// Replace some bytes until past the end, confirm when it fails.
	logic.TestApp(t, `int 4; byte 0x15; box_create;
                byte 0x15; int 1; byte 0x3031; box_replace;
                byte 0x15; int 0; int 4; box_extract;
                byte 0x00303100; ==`, ep)
	logic.TestApp(t, `int 4; byte 0x16; box_create;
                byte 0x16; int 1; byte 0x303132; box_replace;
                byte 0x16; int 0; int 4; box_extract;
                byte 0x00303132; ==`, ep)
	logic.TestApp(t, `int 4; byte 0x17; box_create;
                byte 0x17; int 1; byte 0x30313233; box_replace;
                byte 0x17; int 0; int 4; box_extract;
                byte 0x0030313233; ==`, ep, "replace range")
}

func TestBoxAcrossTxns(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ledger := logic.NewLedger(nil)
	ledger.NewApp(basics.Address{}, 888, basics.AppParams{})
	// After creation in first txn, second one can read it (though it's empty)
	logic.TestApps(t, []string{
		`int 64; byte "self"; box_create; int 1`,
		`byte "self"; int 10; int 4; box_extract; byte 0x00000000; ==`,
	}, nil, 7, ledger)
	// after creation, modification, the third can read it
	logic.TestApps(t, []string{
		`int 64; byte "self"; box_create; int 1`,
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
		`int 64; byte "self"; box_create; int 1`,
		`byte "B"; int 10; int 4; box_extract; byte 0x00000000; ==`,
	}, nil, 7, ledger, logic.NewExpect(1, "invalid Box reference B"))

	// B is available if indexed by 0 in tx[1].Boxes
	group := logic.MakeSampleTxnGroup(logic.MakeSampleTxn(), txntest.Txn{
		Type:          "appl",
		ApplicationID: 10000,
		Boxes:         []transactions.BoxRef{{Index: 0, Name: "B"}},
	}.SignedTxn())
	group[0].Txn.Type = protocol.ApplicationCallTx
	logic.TestApps(t, []string{
		`int 64; byte "self"; box_create; int 1`,
		`byte "B"; int 10; int 4; box_extract; byte 0x00000000; ==`,
	}, group, 7, ledger, logic.NewExpect(1, "no such app"))

	// B is available if listed by appId in tx[1].Boxes
	group = logic.MakeSampleTxnGroup(logic.MakeSampleTxn(), txntest.Txn{
		Type:          "appl",
		ApplicationID: 10000,
		ForeignApps:   []basics.AppIndex{10000},
		Boxes:         []transactions.BoxRef{{Index: 1, Name: "B"}},
	}.SignedTxn())
	group[0].Txn.Type = protocol.ApplicationCallTx
	logic.TestApps(t, []string{
		`int 64; byte "self"; box_create; int 1`,
		`byte "B"; int 10; int 4; box_extract; byte 0x00000000; ==`,
	}, group, 7, ledger, logic.NewExpect(1, "no such app"))

}
