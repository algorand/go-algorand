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
	"github.com/algorand/go-algorand/data/transactions/logic"
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

			basicAppCallApproval := `#pragma version 8
byte "hellobox"
int 10
box_create
pop
int 1`
			basicAppCallClear := `#pragma version 8
int 1`
			basicAppCallClearOps, err := logic.AssembleString(basicAppCallClear)
			require.NoError(t, err)
			basicAppCallApprovalOps, err := logic.AssembleString(basicAppCallApproval)
			require.NoError(t, err)
			// a basic app call
			basicAppCallTxn := txntest.Txn{
				Type:              protocol.ApplicationCallTx,
				Sender:            addrs[0],
				ApprovalProgram:   basicAppCallApproval,
				ClearStateProgram: basicAppCallClear,
				FirstValid:        newBlock.Round(),
				LastValid:         newBlock.Round() + 1000,
				Fee:               minFee,
				GenesisHash:       genHash,
				Note:              []byte("one"),
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
			v6Clear := `#pragma version 6
int 1`
			v6ClearOps, err := logic.AssembleString(v6Clear)
			require.NoError(t, err)
			innerAppCallTxn := txntest.Txn{
				Type:              protocol.ApplicationCallTx,
				Sender:            addrs[0],
				ClearStateProgram: v6Clear,
				FirstValid:        newBlock.Round(),
				LastValid:         newBlock.Round() + 1000,
				Fee:               minFee,
				GenesisHash:       genHash,
				Note:              []byte("three"),
			}
			scenario := testCase.innerAppCallScenario(mocktracer.TestScenarioInfo{
				CallingTxn:   innerAppCallTxn.Txn(),
				MinFee:       minFee,
				CreatedAppID: innerAppID,
			})
			innerAppCallTxn.ApprovalProgram = scenario.Program
			innerAppCallApprovalOps, err := logic.AssembleString(scenario.Program)
			require.NoError(t, err)

			// inner txn with more box mods
			innerAppCallBoxApproval := `#pragma version 8
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
int 1`
			innerAppCallBoxApprovalOps, err := logic.AssembleString(innerAppCallBoxApproval)
			require.NoError(t, err)
			innerAppCallBoxTxn := txntest.Txn{
				Type:              protocol.ApplicationCallTx,
				Sender:            addrs[0],
				ApprovalProgram:   innerAppCallBoxApproval,
				ClearStateProgram: basicAppCallClear,
				FirstValid:        newBlock.Round(),
				LastValid:         newBlock.Round() + 1000,
				Fee:               minFee,
				GenesisHash:       genHash,
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

			secondPayTxn := txntest.Txn{
				Type:        protocol.PaymentTx,
				Sender:      addrs[2],
				Receiver:    addrs[1],
				Amount:      100_000,
				FirstValid:  newBlock.Round(),
				LastValid:   newBlock.Round() + 1000,
				Fee:         minFee,
				GenesisHash: genHash,
			}
			secondTxGroup := transactions.WrapSignedTxnsWithAD([]transactions.SignedTxn{
				secondPayTxn.Txn().Sign(keys[2]),
			})
			err = eval.TransactionGroup(secondTxGroup)
			require.NoError(t, err)

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
								ApprovalProgram:   basicAppCallApprovalOps.Program,
								ClearStateProgram: basicAppCallClearOps.Program,
							},
						},
					},
					{
						Aidx: 3 + offset,
						Addr: addrs[0],
						Params: ledgercore.AppParamsDelta{
							Params: &basics.AppParams{
								ApprovalProgram:   innerAppCallApprovalOps.Program,
								ClearStateProgram: v6ClearOps.Program,
							},
						},
					},
					{
						Aidx: 4 + offset,
						Addr: innerAppAddress,
						Params: ledgercore.AppParamsDelta{
							Params: &basics.AppParams{
								ApprovalProgram:   []byte{0x06, 0x80, 0x01, 0x78, 0xb0, 0x81, 0x01}, // #pragma version 6; pushbytes "x"; log; pushint 1
								ClearStateProgram: v6ClearOps.Program,
							},
						},
					},
					{
						Aidx: innerBoxAppID,
						Addr: addrs[0],
						Params: ledgercore.AppParamsDelta{
							Params: &basics.AppParams{
								ApprovalProgram:   innerAppCallBoxApprovalOps.Program,
								ClearStateProgram: basicAppCallClearOps.Program,
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
			require.Len(t, allDeltas, 2)

			require.Equal(t, expectedAccts.Accts, actualDelta.Accts.Accts)
			require.Equal(t, expectedAccts.AppResources, actualDelta.Accts.AppResources)
			require.Equal(t, expectedAccts.AssetResources, actualDelta.Accts.AssetResources)
			require.Equal(t, expectedKvMods, actualDelta.KvMods)
			require.Equal(t, expectedLeases, actualDelta.Txleases)
		})
	}
}
