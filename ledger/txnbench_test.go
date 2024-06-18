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

package ledger

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

// BenchmarkTxnTypes compares the execution time of various txn types
func BenchmarkTxnTypes(b *testing.B) {
	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.BenchConsensusRange(b, 30, 0, func(b *testing.B, ver int, cv protocol.ConsensusVersion) {
		l := newSimpleLedgerWithConsensusVersion(b, genBalances, cv, config.GetDefaultLocal())
		defer l.Close()

		createasa := txntest.Txn{
			Type:   "acfg",
			Sender: addrs[0],
			AssetParams: basics.AssetParams{
				Total:     1000000,
				Decimals:  3,
				UnitName:  "oz",
				AssetName: "Gold",
				URL:       "https://gold.rush/",

				Manager:  addrs[0],
				Clawback: addrs[0],
				Freeze:   addrs[0],
				Reserve:  addrs[0],
			},
		}

		eval := nextBlock(b, l)
		txn(b, l, eval, &createasa)
		vb := endBlock(b, l, eval)
		asa := vb.Block().Payset[0].ApplyData.ConfigAsset
		require.Positive(b, asa)

		optin1 := txntest.Txn{
			Type:          "axfer",
			Sender:        addrs[1],
			AssetReceiver: addrs[1],
			XferAsset:     asa,
		}
		optin2 := txntest.Txn{
			Type:          "axfer",
			Sender:        addrs[2],
			AssetReceiver: addrs[2],
			XferAsset:     asa,
		}

		eval = nextBlock(b, l)
		txns(b, l, eval, &optin1, &optin2)
		endBlock(b, l, eval)

		createapp1 := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: "int 1",
		}

		eval = nextBlock(b, l)
		txn(b, l, eval, &createapp1)
		vb = endBlock(b, l, eval)
		app1 := vb.Block().Payset[0].ApplyData.ApplicationID
		require.Positive(b, app1)

		createapp10 := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: strings.Repeat("int 1\npop\n", 5) + "int 1",
		}

		eval = nextBlock(b, l)
		txn(b, l, eval, &createapp10)
		vb = endBlock(b, l, eval)
		app10 := vb.Block().Payset[0].ApplyData.ApplicationID
		require.Positive(b, app10)

		createapp100 := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: strings.Repeat("int 1\npop\n", 50) + "int 1",
		}

		eval = nextBlock(b, l)
		txn(b, l, eval, &createapp100)
		vb = endBlock(b, l, eval)
		app100 := vb.Block().Payset[0].ApplyData.ApplicationID
		require.Positive(b, app100)

		createapp700 := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: strings.Repeat("int 1\npop\n", 349) + "int 1",
		}

		eval = nextBlock(b, l)
		txn(b, l, eval, &createapp700)
		vb = endBlock(b, l, eval)
		app700 := vb.Block().Payset[0].ApplyData.ApplicationID
		require.Positive(b, app700)

		createapp700s := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: strings.Repeat("int 1\n", 350) + strings.Repeat("pop\n", 349),
		}

		eval = nextBlock(b, l)
		txn(b, l, eval, &createapp700s)
		vb = endBlock(b, l, eval)
		app700s := vb.Block().Payset[0].ApplyData.ApplicationID
		require.Positive(b, app700s)

		benches := []struct {
			name string
			txn  txntest.Txn
		}{
			{"pay-self", txntest.Txn{
				Type:     "pay",
				Sender:   addrs[0],
				Receiver: addrs[0],
			}},
			{"pay-other", txntest.Txn{
				Type:     "pay",
				Sender:   addrs[0],
				Receiver: addrs[1],
			}},
			{"asa-self", txntest.Txn{
				Type:          "axfer",
				Sender:        addrs[0],
				AssetAmount:   1,
				XferAsset:     asa,
				AssetReceiver: addrs[0],
			}},
			{"asa-other", txntest.Txn{
				Type:          "axfer",
				Sender:        addrs[0],
				XferAsset:     asa,
				AssetAmount:   10,
				AssetReceiver: addrs[1],
			}},
			{"asa-clawback", txntest.Txn{
				Type:          "axfer",
				Sender:        addrs[0],
				XferAsset:     asa,
				AssetAmount:   1,
				AssetSender:   addrs[1],
				AssetReceiver: addrs[2],
			}},
			{"afrz", txntest.Txn{
				Type:          "afrz",
				Sender:        addrs[0],
				FreezeAsset:   asa,
				AssetFrozen:   true,
				FreezeAccount: addrs[1],
			}},
			{"acfg-big", txntest.Txn{
				Type:        "acfg",
				Sender:      addrs[0],
				ConfigAsset: asa,
				AssetParams: basics.AssetParams{
					Manager:  addrs[0],
					Clawback: addrs[0],
					Freeze:   addrs[0],
					Reserve:  addrs[0],
				},
			}},
			{"acfg-small", txntest.Txn{
				Type:        "acfg",
				Sender:      addrs[0],
				ConfigAsset: asa,
				AssetParams: basics.AssetParams{
					Manager: addrs[0],
				},
			}},
			{"call-1", txntest.Txn{
				Type:          "appl",
				Sender:        addrs[0],
				ApplicationID: app1,
			}},
			{"call-10", txntest.Txn{
				Type:          "appl",
				Sender:        addrs[0],
				ApplicationID: app10,
			}},
			{"call-100", txntest.Txn{
				Type:          "appl",
				Sender:        addrs[0],
				ApplicationID: app100,
			}},
			{"call-700", txntest.Txn{
				Type:          "appl",
				Sender:        addrs[0],
				ApplicationID: app700,
			}},
			{"call-700s", txntest.Txn{
				Type:          "appl",
				Sender:        addrs[0],
				ApplicationID: app700s,
			}},
		}

		for _, bench := range benches {
			b.Run(bench.name, func(b *testing.B) {
				b.ReportAllocs()
				t := bench.txn
				eval := nextBlock(b, l)
				fillDefaults(b, l, eval, &t)
				signed := t.SignedTxn()
				for n := 0; n < b.N; n++ {
					signed.Txn.Note = []byte(strconv.Itoa(n))
					err := eval.Transaction(signed, transactions.ApplyData{})
					if errors.Is(err, ledgercore.ErrNoSpace) {
						endBlock(b, l, eval)
						eval = nextBlock(b, l)
					}
				}
				endBlock(b, l, eval)
			})
		}
	})
}
