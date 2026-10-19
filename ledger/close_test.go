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

// TestCloseMinBalancePolicy checks that, while generating (pool admission and
// block assembly), a close-out of an account whose minimum balance is still
// above the base amount is refused. Validation accepts such a close only before
// CloseRequiresBaseMinBalance is enabled.
func TestCloseMinBalancePolicy(t *testing.T) {
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
		deleted := func(l *Ledger, addr basics.Address) {
			rec := lookup(t, l, addr)
			rec.RewardsBase = 0
			a.Equal(basics.AccountData{}, rec)
		}

		// The sponsor and the sink stay below one RewardUnit so that no rewards
		// accrue; that keeps the close's ApplyData empty, which the validation
		// half of this test relies on.
		creator := addrs[0]
		sponsor := basics.Address{0x01, 0x02, 0x03}
		sink := basics.Address{0x04, 0x05, 0x06}
		const sponsorFunds = 400_000
		const fee = 1_000
		dl.txns(
			&txntest.Txn{Type: protocol.PaymentTx, Sender: addrs[1], Receiver: sponsor, Amount: sponsorFunds},
			&txntest.Txn{Type: protocol.PaymentTx, Sender: addrs[1], Receiver: sink, Amount: 200_000},
		)

		appID := dl.createApp(creator, "int 1", basics.StateSchema{NumUint: 1})

		// A third party takes over responsibility for the app's size.
		dl.txn(&txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            sponsor,
			Fee:               fee,
			ApplicationID:     appID,
			OnCompletion:      transactions.UpdateApplicationOC,
			ApprovalProgram:   app(appID).ApprovalProgram,
			ExtraProgramPages: 1,
			GlobalStateSchema: basics.StateSchema{NumUint: 1},
		})
		a.Equal(sponsor, app(appID).SizeSponsor)
		rec := lookup(t, dl.generator, sponsor)
		a.Greater(rec.MinBalance(proto.BalanceRequirements()).Raw, proto.MinBalance)
		a.EqualValues(sponsorFunds-fee, rec.MicroAlgos.Raw)

		close := txntest.Txn{
			Type:             protocol.PaymentTx,
			Sender:           sponsor,
			Fee:              fee,
			Receiver:         sink,
			Amount:           sponsorFunds - 2*fee, // leaves ClosingAmount at zero
			CloseRemainderTo: sink,
		}

		// Generating: refused.
		dl.txn(&close, "cannot close")

		// An ordinary account with only the base minimum balance still closes.
		dl.txn(&txntest.Txn{
			Type:             protocol.PaymentTx,
			Sender:           addrs[2],
			Receiver:         addrs[3],
			CloseRemainderTo: addrs[3],
		})
		deleted(dl.generator, addrs[2])

		// Disable the generation policy to check the consensus rule. Older
		// protocols accept the close; CloseRequiresBaseMinBalance rejects it
		// even during validation.
		dl.beginBlock()
		dl.eval.SetGenerateForTesting(false)
		if proto.CloseRequiresBaseMinBalance {
			txn(t, dl.generator, dl.eval, &close, "cannot close: min balance")
		} else {
			txn(t, dl.generator, dl.eval, &close)
		}
		dl.eval.SetGenerateForTesting(true)
		dl.endBlock()

		if proto.CloseRequiresBaseMinBalance {
			for _, l := range []*Ledger{dl.generator, dl.validator} {
				acct := lookup(t, l, sponsor)
				a.Equal(rec.MicroAlgos, acct.MicroAlgos)
				a.Equal(rec.TotalAppSchema, acct.TotalAppSchema)
				a.Equal(rec.TotalExtraAppPages, acct.TotalExtraAppPages)
			}
		} else {
			deleted(dl.generator, sponsor)
			deleted(dl.validator, sponsor)
		}
		a.Equal(basics.StateSchema{NumUint: 1}, app(appID).GlobalStateSchema)
		a.Equal(sponsor, app(appID).SizeSponsor)

		// Inner transactions reach apply through Perform rather than
		// eval.transaction, so the policy must hold there too. This app's
		// account sponsors appID with an inner update, then tries to close
		// itself with an inner payment.
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
		callCloser("close", "cannot close")
		a.NotZero(lookup(t, dl.generator, closer.Address()).MicroAlgos.Raw)

		// Once the sponsored app is gone, the inner close goes through.
		dl.txn(&txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        creator,
			ApplicationID: appID,
			OnCompletion:  transactions.DeleteApplicationOC,
		})
		callCloser("close")
		deleted(dl.generator, closer.Address())
		deleted(dl.validator, closer.Address())
	})
}
