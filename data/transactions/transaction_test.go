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
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func TestTransaction_EstimateEncodedSize(t *testing.T) {
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
		KeyregTxnFields: KeyregTxnFields{Nonparticipation: true},
	}
	tx.KeyregTxnFields.VoteFirst = 1
	tx.KeyregTxnFields.VoteLast = 300
	tx.KeyregTxnFields.VoteKeyDilution = 1

	tx.KeyregTxnFields.Nonparticipation = true
	return tx
}

func TestGoOnlineGoNonparticipatingContradiction(t *testing.T) {
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

func TestWellFormedErrors(t *testing.T) {
	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	specialAddr := SpecialAddresses{FeeSink: feeSink}
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
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
				Type: protocol.PaymentTx,
				Header: Header{
					Sender: addr1,
					Fee:    basics.MicroAlgos{Raw: 100},
				},
			},
			spec:          specialAddr,
			proto:         curProto,
			expectedError: makeMinFeeErrorf("transaction had fee %d, which is less than the minimum %d", 100, curProto.MinTxnFee),
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
	}
	for _, usecase := range usecases {
		err := usecase.tx.WellFormed(usecase.spec, usecase.proto)
		require.Equal(t, usecase.expectedError, err)
	}
}

var generateFlag = flag.Bool("generate", false, "")

// running test with -generate would generate the matrix used in the test ( without the "correct" errors )
func TestWellFormedKeyRegistrationTx(t *testing.T) {
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
		votePK                                    bool
		selectionPK                               bool
		voteFirst                                 bool
		voteLast                                  bool
		voteKeyDilution                           bool
		nonParticipation                          bool
		supportBecomeNonParticipatingTransactions bool
		enableKeyregCoherencyCheck                bool
		err                                       error
	}
	runTestCase := func(testCase keyRegTestCase) error {
		tx.KeyregTxnFields.VotePK = crypto.OneTimeSignatureVerifier{}
		tx.KeyregTxnFields.SelectionPK = crypto.VRFVerifier{}
		tx.KeyregTxnFields.VoteFirst = basics.Round(0)
		tx.KeyregTxnFields.VoteLast = basics.Round(0)
		tx.KeyregTxnFields.VoteKeyDilution = 0
		tx.KeyregTxnFields.Nonparticipation = false

		if testCase.votePK {
			tx.KeyregTxnFields.VotePK = crypto.OneTimeSignatureVerifier{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
		}
		if testCase.selectionPK {
			tx.KeyregTxnFields.SelectionPK = crypto.VRFVerifier{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
		}
		if testCase.voteFirst {
			tx.KeyregTxnFields.VoteFirst = basics.Round(5)
		}
		if testCase.voteLast {
			tx.KeyregTxnFields.VoteLast = basics.Round(10)
		}
		if testCase.voteKeyDilution {
			tx.KeyregTxnFields.VoteKeyDilution = uint64(10000)
		}
		if testCase.nonParticipation {
			tx.KeyregTxnFields.Nonparticipation = true
		}
		curProto.SupportBecomeNonParticipatingTransactions = testCase.supportBecomeNonParticipatingTransactions
		curProto.EnableKeyregCoherencyCheck = testCase.enableKeyregCoherencyCheck
		return tx.WellFormed(spec, curProto)
	}

	if *generateFlag == true {
		fmt.Printf("keyRegTestCases := []keyRegTestCase{\n")
		idx := 0
		for _, votePK := range []string{"false", "true "} {
			for _, selectionPK := range []string{"false", "true "} {
				for _, voteFirst := range []string{"false", "true "} {
					for _, voteLast := range []string{"false", "true "} {
						for _, voteKeyDilution := range []string{"false", "true "} {
							for _, nonParticipation := range []string{"false", "true "} {
								for _, supportBecomeNonParticipatingTransactions := range []string{"false", "true "} {
									for _, enableKeyregCoherencyCheck := range []string{"false", "true "} {
										outcome := runTestCase(keyRegTestCase{
											votePK != "false",
											selectionPK != "false",
											voteFirst != "false",
											voteLast != "false",
											voteKeyDilution != "false",
											nonParticipation != "false",
											supportBecomeNonParticipatingTransactions != "false",
											enableKeyregCoherencyCheck != "false",
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
										default:
											require.Nil(t, outcome)

										}

										fmt.Printf("/* %d */ keyRegTestCase{votePK:%s, selectionPK:%s, voteFirst:%s, voteLast:%s, voteKeyDilution:%s, nonParticipation:%s, supportBecomeNonParticipatingTransactions:%s, enableKeyregCoherencyCheck:%s, err:%s},\n",
											idx, votePK, selectionPK, voteFirst, voteLast, voteKeyDilution, nonParticipation, supportBecomeNonParticipatingTransactions, enableKeyregCoherencyCheck, errStr)
										idx++
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
		/* 0 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 1 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: nil},
		/* 2 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 3 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/* 4 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 5 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 6 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 7 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/* 8 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 9 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 10 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 11 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 12 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 13 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 14 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 15 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 16 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 17 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 18 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 19 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 20 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 21 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 22 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 23 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 24 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 25 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 26 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 27 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 28 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 29 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 30 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 31 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 32 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 33 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 34 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 35 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 36 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 37 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 38 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 39 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 40 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 41 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 42 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 43 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 44 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 45 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 46 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 47 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 48 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 49 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 50 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 51 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 52 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 53 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 54 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 55 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnOfflineTransactionHasVotingRounds},
		/* 56 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 57 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 58 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 59 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 60 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 61 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 62 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 63 */ keyRegTestCase{votePK: false, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 64 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 65 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 66 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 67 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 68 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 69 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 70 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 71 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 72 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 73 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 74 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 75 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 76 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 77 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 78 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 79 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 80 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 81 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 82 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 83 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 84 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 85 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 86 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 87 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 88 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 89 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 90 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 91 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 92 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 93 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 94 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 95 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 96 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 97 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 98 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 99 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 100 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 101 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 102 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 103 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 104 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 105 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 106 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 107 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 108 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 109 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 110 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 111 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 112 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 113 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 114 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 115 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 116 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 117 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 118 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 119 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 120 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 121 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 122 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 123 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 124 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 125 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 126 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 127 */ keyRegTestCase{votePK: false, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 128 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 129 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 130 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 131 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 132 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 133 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 134 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 135 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 136 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 137 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 138 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 139 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 140 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 141 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 142 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 143 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 144 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 145 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 146 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 147 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 148 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 149 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 150 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 151 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 152 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 153 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 154 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 155 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 156 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 157 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 158 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 159 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 160 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 161 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 162 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 163 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 164 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 165 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 166 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 167 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 168 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 169 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 170 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 171 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 172 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 173 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 174 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 175 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 176 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 177 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 178 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 179 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 180 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 181 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 182 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 183 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 184 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 185 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 186 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 187 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 188 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 189 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 190 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 191 */ keyRegTestCase{votePK: true, selectionPK: false, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 192 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 193 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 194 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 195 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 196 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 197 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 198 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 199 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 200 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 201 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 202 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 203 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 204 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 205 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 206 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 207 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithZeroVoteLast},
		/* 208 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 209 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 210 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 211 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 212 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 213 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 214 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 215 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 216 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 217 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: nil},
		/* 218 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 219 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/* 220 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 221 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 222 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 223 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: false, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 224 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 225 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 226 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 227 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 228 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 229 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 230 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 231 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 232 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 233 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 234 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 235 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 236 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 237 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 238 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 239 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: false, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound},
		/* 240 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 241 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 242 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 243 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 244 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 245 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 246 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 247 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: false, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnNonCoherentVotingKeys},
		/* 248 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: nil},
		/* 249 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: nil},
		/* 250 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: nil},
		/* 251 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: false, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: nil},
		/* 252 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: false, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 253 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: false, enableKeyregCoherencyCheck: true, err: errKeyregTxnUnsupportedSwitchToNonParticipating},
		/* 254 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: false, err: errKeyregTxnGoingOnlineWithNonParticipating},
		/* 255 */ keyRegTestCase{votePK: true, selectionPK: true, voteFirst: true, voteLast: true, voteKeyDilution: true, nonParticipation: true, supportBecomeNonParticipatingTransactions: true, enableKeyregCoherencyCheck: true, err: errKeyregTxnGoingOnlineWithNonParticipating},
	}

	for testcaseIdx, testCase := range keyRegTestCases {
		err := runTestCase(testCase)
		require.Equalf(t, testCase.err, err, "index: %d\ntest case: %#v", testcaseIdx, testCase)
	}
}
