// Copyright (C) 2019-2023 Algorand, Inc.
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

package eval

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTransactionGroupWithDeltaTracer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// In all cases, a group of three transactions is tested. They are:
	//   1. A basic app call transaction
	//   2. A payment transaction
	//   3. An app call transaction that spawns inners. This is from the mocktracer scenarios.

	// We don't care about testing error scenarios here--just exercising different successful txn group evals
	scenario := mocktracer.GetTestScenarios()["none"]
	type tracerTestCase struct {
		name                 string
		innerAppCallScenario mocktracer.TestScenarioGenerator
	}
	var testCases = []tracerTestCase{
		{
			name:                 "noError",
			innerAppCallScenario: scenario,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			// SETUP THE BLOCK
			genesisInitState, addrs, keys := ledgertesting.Genesis(4)

			// newTestLedger uses ConsensusFuture, so we check it to find out if
			// we should use 1001 as the initial resources ID.
			protoVersion := protocol.ConsensusFuture
			proto := config.Consensus[protoVersion]
			offset := basics.AppIndex(0)
			if proto.AppForbidLowResources {
				offset += 1000
			}

			innerAppID := basics.AppIndex(3) + offset
			innerAppAddress := innerAppID.Address()
			appID := basics.AppIndex(1) + offset
			appAddress := appID.Address()
			innerBoxAppID := basics.AppIndex(7) + offset
			innerBoxAppAddress := innerBoxAppID.Address()
			balances := genesisInitState.Accounts
			balances[innerAppAddress] = basics_testing.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1_000_000})
			balances[appAddress] = basics_testing.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1_000_000})

			genesisBalances := bookkeeping.GenesisBalances{
				Balances:    genesisInitState.Accounts,
				FeeSink:     testSinkAddr,
				RewardsPool: testPoolAddr,
				Timestamp:   0,
			}
			l := newTestLedger(t, genesisBalances)
			blkHeader, err := l.BlockHdr(basics.Round(0))
			require.NoError(t, err)
			newBlock := bookkeeping.MakeBlock(blkHeader)
			tracer := MakeTxnGroupDeltaTracer(4)
			eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, tracer)
			require.NoError(t, err)
			eval.validate = true
			eval.generate = true
			genHash := l.GenesisHash()

			// a basic app call
			basicAppCallTxn := txntest.Txn{
				Type:   protocol.ApplicationCallTx,
				Sender: addrs[0],
				ApprovalProgram: `#pragma version 8
byte "hellobox"
int 10
box_create
pop
int 1`,
				ClearStateProgram: `#pragma version 8
int 1`,
				FirstValid:  newBlock.Round(),
				LastValid:   newBlock.Round() + 1000,
				Fee:         minFee,
				GenesisHash: genHash,
				Note:        []byte("one"),
				Boxes: []transactions.BoxRef{{
					Index: 0,
					Name:  []byte("hellobox"),
				}},
			}

			// a non-app call txn
			var txnLease [32]byte
			copy(txnLease[:], "txnLeaseTest")
			payTxn := txntest.Txn{
				Type:             protocol.PaymentTx,
				Sender:           addrs[1],
				Receiver:         addrs[2],
				CloseRemainderTo: addrs[3],
				Amount:           1_000_000,
				FirstValid:       newBlock.Round(),
				LastValid:        newBlock.Round() + 1000,
				Fee:              minFee,
				GenesisHash:      genHash,
				Note:             []byte("two"),
				Lease:            txnLease,
			}
			// an app call with inner txn
			innerAppCallTxn := txntest.Txn{
				Type:   protocol.ApplicationCallTx,
				Sender: addrs[0],
				ClearStateProgram: `#pragma version 6
int 1`,
				FirstValid:  newBlock.Round(),
				LastValid:   newBlock.Round() + 1000,
				Fee:         minFee,
				GenesisHash: genHash,
				Note:        []byte("three"),
			}
			scenario := testCase.innerAppCallScenario(mocktracer.TestScenarioInfo{
				CallingTxn:   innerAppCallTxn.Txn(),
				MinFee:       minFee,
				CreatedAppID: innerAppID,
			})
			innerAppCallTxn.ApprovalProgram = scenario.Program

			// inner txn with more box mods
			innerAppCallBoxTxn := txntest.Txn{
				Type:   protocol.ApplicationCallTx,
				Sender: addrs[0],
				ApprovalProgram: `#pragma version 8
byte "goodbyebox"
int 10
box_create
pop
byte "goodbyebox"
int 0
byte "2"
box_replace
byte "goodbyebox"
box_del
pop
int 1`,
				ClearStateProgram: `#pragma version 8
int 1`,
				FirstValid:  newBlock.Round(),
				LastValid:   newBlock.Round() + 1000,
				Fee:         minFee,
				GenesisHash: genHash,
				Boxes: []transactions.BoxRef{{
					Index: 0,
					Name:  []byte("goodbyebox"),
				}},
			}

			txntest.Group(&basicAppCallTxn, &payTxn, &innerAppCallTxn, &innerAppCallBoxTxn)

			txgroup := transactions.WrapSignedTxnsWithAD([]transactions.SignedTxn{
				basicAppCallTxn.Txn().Sign(keys[0]),
				payTxn.Txn().Sign(keys[1]),
				innerAppCallTxn.Txn().Sign(keys[0]),
				innerAppCallBoxTxn.Txn().Sign(keys[0]),
			})

			require.Len(t, eval.block.Payset, 0)

			err = eval.TransactionGroup(txgroup)
			require.NoError(t, err)
			require.Len(t, eval.block.Payset, 4)

			expectedAccts := ledgercore.AccountDeltas{
				Accts: []ledgercore.BalanceRecord{
					{
						Addr: addrs[0],
						AccountData: ledgercore.AccountData{
							AccountBaseData: ledgercore.AccountBaseData{
								MicroAlgos:     basics.MicroAlgos{Raw: 1666666666663666},
								TotalAppParams: 3,
							},
						},
					},
					{
						Addr: testSinkAddr,
						AccountData: ledgercore.AccountData{
							AccountBaseData: ledgercore.AccountBaseData{
								Status:     basics.Status(2),
								MicroAlgos: basics.MicroAlgos{Raw: 1666666666673666},
							},
						},
					},
					{
						Addr: appAddress,
						AccountData: ledgercore.AccountData{
							AccountBaseData: ledgercore.AccountBaseData{
								MicroAlgos:    basics.MicroAlgos{Raw: 1000000},
								TotalBoxes:    1,
								TotalBoxBytes: 18,
							},
						},
					},
					{
						Addr: addrs[1],
					},
					{
						Addr: addrs[2],
						AccountData: ledgercore.AccountData{
							AccountBaseData: ledgercore.AccountBaseData{
								MicroAlgos: basics.MicroAlgos{Raw: 1666666667666666},
							},
						},
					},
					{
						Addr: addrs[3],
						AccountData: ledgercore.AccountData{
							AccountBaseData: ledgercore.AccountBaseData{
								MicroAlgos: basics.MicroAlgos{Raw: 3333333332332332},
							},
						},
					},
					{
						Addr: innerAppAddress,
						AccountData: ledgercore.AccountData{
							AccountBaseData: ledgercore.AccountBaseData{
								MicroAlgos:     basics.MicroAlgos{Raw: 997000},
								TotalAppParams: 1,
							},
						},
					},
					{
						Addr:        innerBoxAppAddress,
						AccountData: ledgercore.AccountData{},
					},
				},
				AppResources: []ledgercore.AppResourceRecord{
					{
						Aidx: 1 + offset,
						Addr: addrs[0],
						Params: ledgercore.AppParamsDelta{
							Params: &basics.AppParams{
								ApprovalProgram:   []byte{0x08, 0x80, 0x08, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x62, 0x6f, 0x78, 0x81, 0x0a, 0xb9, 0x48, 0x81, 0x01},
								ClearStateProgram: []byte{0x08, 0x81, 0x01},
							},
						},
					},
					{
						Aidx: 3 + offset,
						Addr: addrs[0],
						Params: ledgercore.AppParamsDelta{
							Params: &basics.AppParams{
								ApprovalProgram: []byte{0x06, 0x80, 0x01, 0x61, 0xb0, 0xb1, 0x81, 0x06, 0xb2, 0x10, 0x81, 0x00, 0xb2, 0x19, 0x80, 0x07,
									0x06, 0x80, 0x01, 0x78, 0xb0, 0x81, 0x01, 0xb2, 0x1e, 0x80, 0x03, 0x06, 0x81, 0x01, 0xb2, 0x1f,
									0xb3, 0x80, 0x01, 0x62, 0xb0, 0xb1, 0x81, 0x01, 0xb2, 0x10, 0x81, 0x01, 0xb2, 0x08, 0x32, 0x0a,
									0xb2, 0x07, 0xb6, 0x81, 0x01, 0xb2, 0x10, 0x81, 0x02, 0xb2, 0x08, 0x32, 0x0a, 0xb2, 0x07, 0xb3,
									0x80, 0x01, 0x63, 0xb0, 0x81, 0x01},
								ClearStateProgram: []byte{0x06, 0x81, 0x01},
							},
						},
					},
					{
						Aidx: 4 + offset,
						Addr: innerAppAddress,
						Params: ledgercore.AppParamsDelta{
							Params: &basics.AppParams{
								ApprovalProgram:   []byte{0x06, 0x80, 0x01, 0x78, 0xb0, 0x81, 0x01},
								ClearStateProgram: []byte{0x06, 0x81, 0x01},
							},
						},
					},
					{
						Aidx: innerBoxAppID,
						Addr: addrs[0],
						Params: ledgercore.AppParamsDelta{
							Params: &basics.AppParams{
								ApprovalProgram: []byte{0x08, 0x26, 0x01, 0x0a, 0x67, 0x6f, 0x6f, 0x64, 0x62, 0x79, 0x65, 0x62, 0x6f, 0x78, 0x28, 0x81,
									0x0a, 0xb9, 0x48, 0x28, 0x81, 0x00, 0x80, 0x01, 0x32, 0xbb, 0x28, 0xbc, 0x48, 0x81, 0x01},
								ClearStateProgram: []byte{0x08, 0x81, 0x01},
							},
						},
					},
				},
			}
			expectedKvMods := map[string]ledgercore.KvValueDelta{
				"bx:\x00\x00\x00\x00\x00\x00\x03\xe9hellobox": {
					OldData: []uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Data:    []uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
				"bx:\x00\x00\x00\x00\x00\x00\x03\xefgoodbyebox": {
					OldData: nil,
					Data:    nil,
				},
			}
			expectedLeases := map[ledgercore.Txlease]basics.Round{
				{Sender: payTxn.Sender, Lease: payTxn.Lease}: payTxn.LastValid,
			}

			actualDelta, err := tracer.GetDeltaForID(crypto.Digest(txgroup[0].ID()))
			require.NoError(t, err)
			_, err = tracer.GetDeltaForID(crypto.Digest(txgroup[1].ID()))
			require.NoError(t, err)
			_, err = tracer.GetDeltaForID(crypto.Digest(txgroup[2].ID()))
			require.NoError(t, err)
			allDeltas, err := tracer.GetDeltasForRound(basics.Round(1))
			require.NoError(t, err)
			require.Len(t, allDeltas, 1)

			require.Equal(t, expectedAccts.Accts, actualDelta.Accts.Accts)
			require.Equal(t, expectedAccts.AppResources, actualDelta.Accts.AppResources)
			require.Equal(t, expectedAccts.AssetResources, actualDelta.Accts.AssetResources)
			require.Equal(t, expectedKvMods, actualDelta.KvMods)
			require.Equal(t, expectedLeases, actualDelta.Txleases)
		})
	}
}
