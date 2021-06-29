// Copyright (C) 2019-2021 Algorand, Inc.
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

package transactions

import (
	"flag"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
   "github.com/algorand/go-algorand/testPartitioning"
)

func TestTransaction_EstimateEncodedSize(t *testing.T) {
   testPartitioning.PartitionTest(t)

	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	buf := make([]byte, 10)
	crypto.RandBytes(buf[:])

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	tx := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:     addr,
			Fee:        basics.MicroAlgos{Raw: 100},
			FirstValid: basics.Round(1000),
			LastValid:  basics.Round(1000 + proto.MaxTxnLife),
			Note:       buf,
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: addr,
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}

	require.Equal(t, 200, tx.EstimateEncodedSize())
}

func generateDummyGoNonparticpatingTransaction(addr basics.Address) (tx Transaction) {
	buf := make([]byte, 10)
	crypto.RandBytes(buf[:])

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	tx = Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: Header{
			Sender:     addr,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 1,
			LastValid:  300,
		},
		KeyregTxnFields: KeyregTxnFields{
			Nonparticipation: true,
			VoteFirst:        0,
			VoteLast:         0,
		},
	}

	tx.KeyregTxnFields.Nonparticipation = true
	return tx
}

func TestGoOnlineGoNonparticipatingContradiction(t *testing.T) {
   testPartitioning.PartitionTest(t)

	// addr has no significance here other than being a normal valid address
	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	tx := generateDummyGoNonparticpatingTransaction(addr)
	// Generate keys, they don't need to be good or secure, just present
	v := crypto.GenerateOneTimeSignatureSecrets(1, 1)
	// Also generate a new VRF key
	vrf := crypto.GenerateVRFSecrets()
	tx.KeyregTxnFields = KeyregTxnFields{
		VotePK:           v.OneTimeSignatureVerifier,
		SelectionPK:      vrf.PK,
		Nonparticipation: true,
	}
	// this tx tries to both register keys to go online, and mark an account as non-participating.
	// it is not well-formed.
	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	err = tx.WellFormed(SpecialAddresses{FeeSink: feeSink}, config.Consensus[protocol.ConsensusCurrentVersion])
	require.Error(t, err)
}

func TestGoNonparticipatingWellFormed(t *testing.T) {
   testPartitioning.PartitionTest(t)

	// addr has no significance here other than being a normal valid address
	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	tx := generateDummyGoNonparticpatingTransaction(addr)
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]

	if !curProto.SupportBecomeNonParticipatingTransactions {
		t.Skipf("Skipping rest of test because current protocol version %v does not support become-nonparticipating transactions", protocol.ConsensusCurrentVersion)
	}

	// this tx is well-formed
	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	err = tx.WellFormed(SpecialAddresses{FeeSink: feeSink}, curProto)
	require.NoError(t, err)
	// but it should stop being well-formed if the protocol does not support it
	curProto.SupportBecomeNonParticipatingTransactions = false
	err = tx.WellFormed(SpecialAddresses{FeeSink: feeSink}, curProto)
	require.Error(t, err)
}

func TestAppCallCreateWellFormed(t *testing.T) {
   testPartitioning.PartitionTest(t)

	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	specialAddr := SpecialAddresses{FeeSink: feeSink}
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	futureProto := config.Consensus[protocol.ConsensusFuture]
	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)
	usecases := []struct {
		tx            Transaction
		spec          SpecialAddresses
		proto         config.ConsensusParams
		expectedError error
	}{
		{
			tx: Transaction{
				Type: protocol.ApplicationCallTx,
				Header: Header{
					Sender:     addr1,
					Fee:        basics.MicroAlgos{Raw: 1000},
					LastValid:  105,
					FirstValid: 100,
				},
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 0,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
				},
			},
			spec:  specialAddr,
			proto: curProto,
		},
		{
			tx: Transaction{
				Type: protocol.ApplicationCallTx,
				Header: Header{
					Sender:     addr1,
					Fee:        basics.MicroAlgos{Raw: 1000},
					LastValid:  105,
					FirstValid: 100,
				},
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 0,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 0,
				},
			},
			spec:  specialAddr,
			proto: curProto,
		},
		{
			tx: Transaction{
				Type: protocol.ApplicationCallTx,
				Header: Header{
					Sender:     addr1,
					Fee:        basics.MicroAlgos{Raw: 1000},
					LastValid:  105,
					FirstValid: 100,
				},
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 0,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 3,
				},
			},
			spec:  specialAddr,
			proto: futureProto,
		},
		{
			tx: Transaction{
				Type: protocol.ApplicationCallTx,
				Header: Header{
					Sender:     addr1,
					Fee:        basics.MicroAlgos{Raw: 1000},
					LastValid:  105,
					FirstValid: 100,
				},
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 0,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 0,
				},
			},
			spec:  specialAddr,
			proto: futureProto,
		},
	}
	for _, usecase := range usecases {
		err := usecase.tx.WellFormed(usecase.spec, usecase.proto)
		require.NoError(t, err)
	}
}

func TestWellFormedErrors(t *testing.T) {
   testPartitioning.PartitionTest(t)

	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	specialAddr := SpecialAddresses{FeeSink: feeSink}
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	futureProto := config.Consensus[protocol.ConsensusFuture]
	protoV27 := config.Consensus[protocol.ConsensusV27]
	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)
	okHeader := Header{
		Sender:     addr1,
		Fee:        basics.MicroAlgos{Raw: 1000},
		LastValid:  105,
		FirstValid: 100,
	}
	usecases := []struct {
		tx            Transaction
		spec          SpecialAddresses
		proto         config.ConsensusParams
		expectedError error
	}{
		{
			tx: Transaction{
				Type: protocol.PaymentTx,
				Header: Header{
					Sender: addr1,
					Fee:    basics.MicroAlgos{Raw: 100},
				},
			},
			spec:          specialAddr,
			proto:         protoV27,
			expectedError: makeMinFeeErrorf("transaction had fee %d, which is less than the minimum %d", 100, curProto.MinTxnFee),
		},
		{
			tx: Transaction{
				Type: protocol.PaymentTx,
				Header: Header{
					Sender: addr1,
					Fee:    basics.MicroAlgos{Raw: 100},
				},
			},
			spec:  specialAddr,
			proto: curProto,
		},
		{
			tx: Transaction{
				Type: protocol.PaymentTx,
				Header: Header{
					Sender:     addr1,
					Fee:        basics.MicroAlgos{Raw: 1000},
					LastValid:  100,
					FirstValid: 105,
				},
			},
			spec:          specialAddr,
			proto:         curProto,
			expectedError: fmt.Errorf("transaction invalid range (%d--%d)", 105, 100),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 0, // creation
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 1,
				},
			},
			spec:          specialAddr,
			proto:         protoV27,
			expectedError: fmt.Errorf("tx.ExtraProgramPages too large, max number of extra pages is %d", protoV27.MaxExtraAppProgramPages),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     0, // creation
					ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
					ClearStateProgram: []byte("junk"),
				},
			},
			spec:          specialAddr,
			proto:         protoV27,
			expectedError: fmt.Errorf("approval program too long. max len 1024 bytes"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     0, // creation
					ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
					ClearStateProgram: []byte("junk"),
				},
			},
			spec:  specialAddr,
			proto: futureProto,
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     0, // creation
					ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
					ClearStateProgram: []byte(strings.Repeat("X", 1025)),
				},
			},
			spec:          specialAddr,
			proto:         futureProto,
			expectedError: fmt.Errorf("app programs too long. max total len 2048 bytes"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     0, // creation
					ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
					ClearStateProgram: []byte(strings.Repeat("X", 1025)),
					ExtraProgramPages: 1,
				},
			},
			spec:  specialAddr,
			proto: futureProto,
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 1,
				},
			},
			spec:          specialAddr,
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.ExtraProgramPages is immutable"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 0,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 4,
				},
			},
			spec:          specialAddr,
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.ExtraProgramPages too large, max number of extra pages is %d", futureProto.MaxExtraAppProgramPages),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					ForeignApps:   []basics.AppIndex{10, 11},
				},
			},
			spec:  specialAddr,
			proto: protoV27,
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					ForeignApps:   []basics.AppIndex{10, 11, 12},
				},
			},
			spec:          specialAddr,
			proto:         protoV27,
			expectedError: fmt.Errorf("tx.ForeignApps too long, max number of foreign apps is 2"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					ForeignApps:   []basics.AppIndex{10, 11, 12, 13, 14, 15, 16, 17},
				},
			},
			spec:  specialAddr,
			proto: futureProto,
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					ForeignAssets: []basics.AssetIndex{14, 15, 16, 17, 18, 19, 20, 21, 22},
				},
			},
			spec:          specialAddr,
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.ForeignAssets too long, max number of foreign assets is 8"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					Accounts:      []basics.Address{{}, {}, {}},
					ForeignApps:   []basics.AppIndex{14, 15, 16, 17},
					ForeignAssets: []basics.AssetIndex{14, 15, 16, 17},
				},
			},
			spec:          specialAddr,
			proto:         futureProto,
			expectedError: fmt.Errorf("tx has too many references, max is 8"),
		},
	}
	for _, usecase := range usecases {
		err := usecase.tx.WellFormed(usecase.spec, usecase.proto)
		require.Equal(t, usecase.expectedError, err)
	}
}

var generateFlag = flag.Bool("generate", false, "")

// running test with -generate would generate the matrix used in the test ( without the "correct" errors )
func TestWellFormedKeyRegistrationTx(t *testing.T) {
   testPartitioning.PartitionTest(t)

	flag.Parse()

	// addr has no significance here other than being a normal valid address
	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	tx := generateDummyGoNonparticpatingTransaction(addr)
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	spec := SpecialAddresses{FeeSink: feeSink}
	if !curProto.SupportBecomeNonParticipatingTransactions {
		t.Skipf("Skipping rest of test because current protocol version %v does not support become-nonparticipating transactions", protocol.ConsensusCurrentVersion)
	}

	// this tx is well-formed
	err = tx.WellFormed(spec, curProto)
	require.NoError(t, err)

	type keyRegTestCase struct {
		votePK                                    crypto.OneTimeSignatureVerifier
		selectionPK                               crypto.VRFVerifier
		voteFirst                                 basics.Round
		voteLast                                  basics.Round
		lastValid                                 basics.Round
		voteKeyDilution                           uint64
		nonParticipation                          bool
		supportBecomeNonParticipatingTransactions bool
		enableKeyregCoherencyCheck                bool
		err                                       error
	}
	votePKValue := crypto.OneTimeSignatureVerifier{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	selectionPKValue := crypto.VRFVerifier{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

	runTestCase := func(testCase keyRegTestCase) error {
		tx.KeyregTxnFields.VotePK = testCase.votePK
		tx.KeyregTxnFields.SelectionPK = testCase.selectionPK
		tx.KeyregTxnFields.VoteFirst = testCase.voteFirst
		tx.KeyregTxnFields.VoteLast = testCase.voteLast
		tx.KeyregTxnFields.VoteKeyDilution = testCase.voteKeyDilution
		tx.KeyregTxnFields.Nonparticipation = testCase.nonParticipation
		tx.LastValid = testCase.lastValid

		curProto.SupportBecomeNonParticipatingTransactions = testCase.supportBecomeNonParticipatingTransactions
		curProto.EnableKeyregCoherencyCheck = testCase.enableKeyregCoherencyCheck
		return tx.WellFormed(spec, curProto)
	}

	if *generateFlag == true {
		fmt.Printf("keyRegTestCases := []keyRegTestCase{\n")
		idx := 0
		for _, votePK := range []crypto.OneTimeSignatureVerifier{crypto.OneTimeSignatureVerifier{}, votePKValue} {
			for _, selectionPK := range []crypto.VRFVerifier{crypto.VRFVerifier{}, selectionPKValue} {
				for _, voteFirst := range []basics.Round{basics.Round(0), basics.Round(5)} {
					for _, voteLast := range []basics.Round{basics.Round(0), basics.Round(10)} {
						for _, lastValid := range []basics.Round{basics.Round(4), basics.Round(3)} {
							for _, voteKeyDilution := range []uint64{0, 10000} {
								for _, nonParticipation := range []bool{false, true} {
									for _, supportBecomeNonParticipatingTransactions := range []bool{false, true} {
										for _, enableKeyregCoherencyCheck := range []bool{false, true} {
											outcome := runTestCase(keyRegTestCase{
												votePK,
												selectionPK,
												voteFirst,
												voteLast,
												lastValid,
												voteKeyDilution,
												nonParticipation,
												supportBecomeNonParticipatingTransactions,
												enableKeyregCoherencyCheck,
												nil})
											errStr := "nil"
											switch outcome {
											case errKeyregTxnUnsupportedSwitchToNonParticipating:
												errStr = "errKeyregTxnUnsupportedSwitchToNonParticipating"
											case errKeyregTxnGoingOnlineWithNonParticipating:
												errStr = "errKeyregTxnGoingOnlineWithNonParticipating"
											case errKeyregTxnNonCoherentVotingKeys:
												errStr = "errKeyregTxnNonCoherentVotingKeys"
											case errKeyregTxnOfflineTransactionHasVotingRounds:
												errStr = "errKeyregTxnOfflineTransactionHasVotingRounds"
											case errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound:
												errStr = "errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound"
											case errKeyregTxnGoingOnlineWithZeroVoteLast:
												errStr = "errKeyregTxnGoingOnlineWithZeroVoteLast"
											case errKeyregTxnGoingOnlineWithNonParticipating:
												errStr = "errKeyregTxnGoingOnlineWithNonParticipating"
											case errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid:
												errStr = "errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid"
											default:
												require.Nil(t, outcome)

											}
											s := "/* %3d */ keyRegTestCase{votePK:"
											if votePK == votePKValue {
												s += "votePKValue"
											} else {
												s += "crypto.OneTimeSignatureVerifier{}"
											}
											s += ", selectionPK:"
											if selectionPK == selectionPKValue {
												s += "selectionPKValue"
											} else {
												s += "crypto.VRFVerifier{}"
											}
											s = fmt.Sprintf("%s, voteFirst:basics.Round(%2d), voteLast:basics.Round(%2d), lastValid:basics.Round(%2d), voteKeyDilution: %5d, nonParticipation: %v,supportBecomeNonParticipatingTransactions:%v, enableKeyregCoherencyCheck:%v, err:%s},\n",
												s, voteFirst, voteLast, lastValid, voteKeyDilution, nonParticipation, supportBecomeNonParticipatingTransactions, enableKeyregCoherencyCheck, errStr)
											fmt.Printf(s, idx)
											idx++
										}
									}
								}
							}
						}
					}
				}
			}
		}
		fmt.Printf("}\n")
		return
	}
	keyRegTestCases := []keyRegTestCase{
		/*   0 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*   1 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: nil},
		/*   2 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*   3 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/*   4 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*   5 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*   6 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*   7 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/*   8 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*   9 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  10 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  11 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  12 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  13 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  14 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  15 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  16 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  17 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: nil},
		/*  18 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  19 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/*  20 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  21 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  22 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  23 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/*  24 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  25 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  26 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  27 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  28 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  29 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  30 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  31 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  32 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  33 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  34 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  35 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  36 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  37 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  38 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  39 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  40 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  41 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  42 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  43 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  44 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  45 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  46 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  47 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  48 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  49 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  50 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  51 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  52 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  53 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  54 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  55 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  56 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  57 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  58 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  59 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  60 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  61 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  62 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  63 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/*  64 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  65 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  66 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  67 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  68 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  69 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  70 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  71 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  72 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  73 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  74 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  75 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  76 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  77 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  78 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  79 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  80 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  81 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  82 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  83 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  84 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  85 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  86 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  87 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  88 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  89 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  90 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  91 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  92 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/*  93 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  94 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  95 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/*  96 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/*  97 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/*  98 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/*  99 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 100 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 101 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 102 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 103 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 104 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 105 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 106 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 107 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 108 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 109 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 110 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 111 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 112 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 113 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 114 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 115 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 116 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 117 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 118 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 119 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 120 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 121 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 122 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 123 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 124 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 125 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 126 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 127 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 128 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 129 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 130 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 131 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 132 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 133 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 134 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 135 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 136 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 137 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 138 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 139 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 140 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 141 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 142 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 143 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 144 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 145 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 146 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 147 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 148 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 149 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 150 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 151 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 152 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 153 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 154 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 155 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 156 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 157 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 158 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 159 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 160 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 161 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 162 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 163 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 164 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 165 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 166 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 167 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 168 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 169 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 170 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 171 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 172 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 173 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 174 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 175 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 176 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 177 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 178 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 179 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 180 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 181 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 182 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 183 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 184 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 185 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 186 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 187 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 188 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 189 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 190 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 191 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 192 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 193 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 194 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 195 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 196 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 197 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 198 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 199 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 200 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 201 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 202 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 203 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 204 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 205 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 206 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 207 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 208 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 209 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 210 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 211 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 212 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 213 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 214 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 215 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 216 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 217 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 218 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 219 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 220 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 221 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 222 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 223 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 224 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 225 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 226 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 227 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 228 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 229 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 230 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 231 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 232 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 233 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 234 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 235 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 236 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 237 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 238 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 239 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 240 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 241 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 242 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 243 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 244 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 245 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 246 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 247 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 248 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 249 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 250 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 251 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 252 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 253 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 254 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 255 */ keyRegTestCase{votePK: crypto.OneTimeSignatureVerifier{}, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 256 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 257 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 258 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 259 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 260 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 261 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 262 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 263 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 264 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 265 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 266 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 267 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 268 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 269 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 270 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 271 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 272 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 273 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 274 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 275 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 276 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 277 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 278 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 279 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 280 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 281 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 282 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 283 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 284 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 285 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 286 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 287 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 288 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 289 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 290 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 291 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 292 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 293 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 294 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 295 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 296 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 297 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 298 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 299 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 300 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 301 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 302 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 303 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 304 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 305 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 306 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 307 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 308 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 309 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 310 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 311 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 312 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 313 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 314 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 315 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 316 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 317 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 318 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 319 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 320 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 321 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 322 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 323 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 324 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 325 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 326 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 327 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 328 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 329 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 330 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 331 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 332 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 333 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 334 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 335 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 336 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 337 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 338 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 339 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 340 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 341 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 342 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 343 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 344 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 345 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 346 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 347 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 348 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 349 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 350 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 351 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 352 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 353 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 354 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 355 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 356 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 357 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 358 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 359 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 360 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 361 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 362 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 363 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 364 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 365 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 366 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 367 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 368 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 369 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 370 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 371 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 372 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 373 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 374 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 375 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 376 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 377 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 378 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 379 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 380 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 381 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 382 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 383 */ keyRegTestCase{votePK: votePKValue, selectionPK: crypto.VRFVerifier{}, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 384 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 385 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 386 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 387 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 388 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 389 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 390 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 391 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 392 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 393 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 394 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 395 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 396 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 397 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 398 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 399 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 400 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 401 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 402 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 403 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 404 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 405 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 406 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 407 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 408 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 409 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 410 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 411 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 412 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 413 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 414 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 415 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 416 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 417 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 418 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 419 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 420 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 421 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 422 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 423 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 424 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 425 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: nil},
		/* 426 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 427 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/* 428 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 429 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 430 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 431 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 432 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 433 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 434 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 435 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 436 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 437 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 438 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 439 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 440 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 441 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: nil},
		/* 442 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 443 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/* 444 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 445 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 446 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 447 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(0), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 448 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 449 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 450 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 451 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 452 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 453 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 454 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 455 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 456 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 457 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 458 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 459 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 460 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 461 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 462 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 463 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 464 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 465 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 466 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 467 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 468 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 469 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 470 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 471 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 472 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 473 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 474 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 475 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 476 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 477 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 478 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 479 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(0), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 480 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 481 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 482 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 483 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 484 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 485 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 486 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 487 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 488 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 489 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: nil},
		/* 490 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 491 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/* 492 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 493 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 494 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 495 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(4), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 496 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 497 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 498 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 499 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 500 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 501 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 502 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 503 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 0, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 504 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 505 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid},
		/* 506 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 507 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid},
		/* 508 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 509 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid},
		/* 510 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 511 */ keyRegTestCase{votePK: votePKValue, selectionPK: selectionPKValue, voteFirst: basics.Round(5), voteLast: basics.Round(10), lastValid: basics.Round(3), voteKeyDilution: 10000, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid},
	}
	for testcaseIdx, testCase := range keyRegTestCases {
		err := runTestCase(testCase)
		require.Equalf(t, testCase.err, err, "index: %d\ntest case: %#v", testcaseIdx, testCase)
	}
}
