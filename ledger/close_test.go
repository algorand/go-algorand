// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestInnerCloseRequiresBaseMinBalance checks CloseRequiresBaseMinBalance on
// the inner-transaction path: an app account that sponsors another app's size
// through an inner update cannot close itself with an inner payment.
func TestInnerCloseRequiresBaseMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, 42, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		proto := config.Consensus[cv]
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()
		a := require.New(t)

		app := func(id basics.AppIndex) basics.AppParams {
			c, _, err := dl.generator.GetCreator(basics.CreatableIndex(id), basics.AppCreatable)
			a.NoError(err)
			ap, err := dl.generator.LookupApplication(dl.generator.Latest(), c, id)
			a.NoError(err)
			return *ap.AppParams
		}
		// deleted asserts that addr has no balance record left. LookupLatest
		// reports the current rewards level even for a missing record, so that
		// field is ignored.
		deleted := func(addr basics.Address) {
			for _, l := range []*Ledger{dl.generator, dl.validator} {
				rec := lookup(t, l, addr)
				rec.RewardsBase = 0
				a.Equal(basics.AccountData{}, rec)
			}
		}

		creator, sink := addrs[0], addrs[1]
		appID := dl.createApp(creator, "int 1", basics.StateSchema{NumUint: 1})

		// closer's account sponsors appID with an inner update, then tries to
		// close itself with an inner payment.
		closer := dl.fundedApp(creator, 3_000_000, main(`
txn ApplicationArgs 0; byte "close"; ==; bnz close
itxn_begin
int appl;              itxn_field TypeEnum
txn Applications 1;    itxn_field ApplicationID
int UpdateApplication; itxn_field OnCompletion
txn Applications 1; app_params_get AppApprovalProgram;   assert; itxn_field ApprovalProgram
txn Applications 1; app_params_get AppClearStateProgram; assert; itxn_field ClearStateProgram
int 1;                 itxn_field ExtraProgramPages
itxn_submit
b end
close:
itxn_begin
int pay;               itxn_field TypeEnum
txn Accounts 1;        itxn_field Receiver
txn Accounts 1;        itxn_field CloseRemainderTo
itxn_submit
`))
		callCloser := func(arg string, problem ...string) {
			dl.txn(&txntest.Txn{
				Type:            protocol.ApplicationCallTx,
				Sender:          creator,
				ApplicationID:   closer,
				ApplicationArgs: [][]byte{[]byte(arg)},
				ForeignApps:     []basics.AppIndex{appID},
				Accounts:        []basics.Address{sink},
			}, problem...)
		}
		callCloser("update")
		a.Equal(closer.Address(), app(appID).SizeSponsor)
		rec := lookup(t, dl.generator, closer.Address())
		a.Greater(rec.MinBalance(proto.BalanceRequirements()).Raw, proto.MinBalance)

		if !proto.CloseRequiresBaseMinBalance {
			// The legacy checks allow the close; the app keeps its size with
			// nobody holding the minimum balance for it.
			callCloser("close")
			deleted(closer.Address())
			a.EqualValues(1, app(appID).ExtraProgramPages)
			a.Equal(closer.Address(), app(appID).SizeSponsor)
			return
		}

		callCloser("close", "cannot close: min balance")
		a.Equal(rec, lookup(t, dl.generator, closer.Address()))

		// Once the sponsored app is gone, the inner close goes through.
		dl.txn(&txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        creator,
			ApplicationID: appID,
			OnCompletion:  transactions.DeleteApplicationOC,
		})
		callCloser("close")
		deleted(closer.Address())
	})
}
