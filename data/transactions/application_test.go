// Copyright (C) 2019-2025 Algorand, Inc.
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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestApplicationCallFieldsNotChanged(t *testing.T) {
	partitiontest.PartitionTest(t)

	af := ApplicationCallTxnFields{}
	s := reflect.ValueOf(&af).Elem()

	if s.NumField() != 14 {
		t.Errorf("You added or removed a field from transactions.ApplicationCallTxnFields. " +
			"Please ensure you have updated the Empty() method and then " +
			"fix this test")
	}
}

func TestApplicationCallFieldsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ac := ApplicationCallTxnFields{}
	a.True(ac.Empty())

	ac.ApplicationID = 1
	a.False(ac.Empty())

	ac.ApplicationID = 0
	ac.OnCompletion = 1
	a.False(ac.Empty())

	ac.OnCompletion = 0
	ac.ApplicationArgs = make([][]byte, 1)
	a.False(ac.Empty())

	ac.ApplicationArgs = nil
	ac.RejectVersion = 1
	a.False(ac.Empty())

	ac.RejectVersion = 0
	ac.Accounts = make([]basics.Address, 1)
	a.False(ac.Empty())

	ac.Accounts = nil
	ac.ForeignApps = make([]basics.AppIndex, 1)
	a.False(ac.Empty())

	ac.ForeignApps = nil
	ac.ForeignAssets = make([]basics.AssetIndex, 1)
	a.False(ac.Empty())

	ac.ForeignAssets = nil
	ac.LocalStateSchema = basics.StateSchema{NumUint: 1}
	a.False(ac.Empty())

	ac.LocalStateSchema = basics.StateSchema{}
	ac.Boxes = make([]BoxRef, 1)
	a.False(ac.Empty())

	ac.Boxes = nil
	ac.GlobalStateSchema = basics.StateSchema{NumUint: 1}
	a.False(ac.Empty())

	ac.GlobalStateSchema = basics.StateSchema{}
	ac.ApprovalProgram = []byte{1}
	a.False(ac.Empty())

	ac.ApprovalProgram = []byte{}
	a.False(ac.Empty())

	ac.ApprovalProgram = nil
	ac.ClearStateProgram = []byte{1}
	a.False(ac.Empty())

	ac.ClearStateProgram = []byte{}
	a.False(ac.Empty())

	ac.ClearStateProgram = nil
	a.True(ac.Empty())
}

func TestEncodedAppTxnAllocationBounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	// ensure that all the supported protocols have value limits less or
	// equal to their corresponding codec allocbounds
	for protoVer, proto := range config.Consensus {
		if proto.MaxAppArgs > encodedMaxApplicationArgs {
			require.Failf(t, "proto.MaxAppArgs > encodedMaxApplicationArgs", "protocol version = %s", protoVer)
		}
		if proto.MaxAppTxnAccounts > encodedMaxAccounts {
			require.Failf(t, "proto.MaxAppTxnAccounts > encodedMaxAccounts", "protocol version = %s", protoVer)
		}
		if proto.MaxAppTxnForeignApps > encodedMaxForeignApps {
			require.Failf(t, "proto.MaxAppTxnForeignApps > encodedMaxForeignApps", "protocol version = %s", protoVer)
		}
		if proto.MaxAppTxnForeignAssets > encodedMaxForeignAssets {
			require.Failf(t, "proto.MaxAppTxnForeignAssets > encodedMaxForeignAssets", "protocol version = %s", protoVer)
		}
		if proto.MaxAppBoxReferences > encodedMaxBoxes {
			require.Failf(t, "proto.MaxAppBoxReferences > encodedMaxBoxes", "protocol version = %s", protoVer)
		}
	}
}

func TestAppCallVersioningWellFormed(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	preVersion := protocol.ConsensusV40
	v5 := []byte{0x05}

	cases := []struct {
		expectedError string
		cv            protocol.ConsensusVersion // defaults to future if not set
		ac            ApplicationCallTxnFields
	}{
		{
			cv: preVersion,
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				RejectVersion: 0,
			},
		},
		{
			expectedError: "tx.RejectVersion is not supported",
			cv:            preVersion,
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				RejectVersion: 1,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				RejectVersion: 0,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				RejectVersion: 1,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				RejectVersion:     0,
			},
		},
		{
			expectedError: "tx.RejectVersion cannot be set during creation",
			ac: ApplicationCallTxnFields{
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				RejectVersion:     1,
			},
		},
	}
	for i, tc := range cases {
		name := fmt.Sprintf("i=%d", i)
		if tc.expectedError != "" {
			name = tc.expectedError
		}
		t.Run(name, func(t *testing.T) {
			cv := tc.cv
			if cv == "" {
				cv = protocol.ConsensusFuture
			}
			err := tc.ac.wellFormed(config.Consensus[cv])
			if tc.expectedError != "" {
				require.ErrorContains(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAppCallCreateWellFormed(t *testing.T) {
	partitiontest.PartitionTest(t)

	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	futureProto := config.Consensus[protocol.ConsensusFuture]
	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)
	v5 := []byte{0x05}
	v6 := []byte{0x06}

	usecases := []struct {
		tx            Transaction
		proto         config.ConsensusParams
		expectedError string
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
					ApplicationID:     0,
					ApprovalProgram:   v5,
					ClearStateProgram: v5,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
				},
			},
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
					ApplicationID:     0,
					ApprovalProgram:   v5,
					ClearStateProgram: v5,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 0,
				},
			},
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
					ApplicationID:     0,
					ApprovalProgram:   v5,
					ClearStateProgram: v5,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 3,
				},
			},
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
					ApplicationID:     0,
					ApprovalProgram:   v5,
					ClearStateProgram: v5,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 0,
				},
			},
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
					ApprovalProgram:   v5,
					ClearStateProgram: v6,
				},
			},
			proto:         futureProto,
			expectedError: "mismatch",
		},
	}
	for i, usecase := range usecases {
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			err := usecase.tx.WellFormed(SpecialAddresses{}, usecase.proto)
			if usecase.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), usecase.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWellFormedErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	futureProto := config.Consensus[protocol.ConsensusFuture]
	protoV27 := config.Consensus[protocol.ConsensusV27]
	protoV28 := config.Consensus[protocol.ConsensusV28]
	protoV32 := config.Consensus[protocol.ConsensusV32]
	protoV36 := config.Consensus[protocol.ConsensusV36]
	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)
	v5 := []byte{0x05}
	okHeader := Header{
		Sender:     addr1,
		Fee:        basics.MicroAlgos{Raw: 1000},
		LastValid:  105,
		FirstValid: 100,
	}
	usecases := []struct {
		tx            Transaction
		proto         config.ConsensusParams
		expectedError error
	}{
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     0, // creation
					ApprovalProgram:   v5,
					ClearStateProgram: v5,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 1,
				},
			},
			proto:         protoV27,
			expectedError: fmt.Errorf("tx.ExtraProgramPages exceeds MaxExtraAppProgramPages = %d", protoV27.MaxExtraAppProgramPages),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     0, // creation
					ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
					ClearStateProgram: []byte("Xjunk"),
				},
			},
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
					ClearStateProgram: []byte("Xjunk"),
				},
			},
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
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.ExtraProgramPages is immutable"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     0,
					ApprovalProgram:   v5,
					ClearStateProgram: v5,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 4,
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.ExtraProgramPages exceeds MaxExtraAppProgramPages = %d", futureProto.MaxExtraAppProgramPages),
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
			proto:         futureProto,
			expectedError: fmt.Errorf("tx references exceed MaxAppTotalTxnReferences = 8"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     1,
					ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
					ClearStateProgram: []byte(strings.Repeat("X", 1025)),
					ExtraProgramPages: 0,
					OnCompletion:      UpdateApplicationOC,
				},
			},
			proto:         protoV28,
			expectedError: fmt.Errorf("app programs too long. max total len %d bytes", curProto.MaxAppProgramLen),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     1,
					ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
					ClearStateProgram: []byte(strings.Repeat("X", 1025)),
					ExtraProgramPages: 0,
					OnCompletion:      UpdateApplicationOC,
				},
			},
			proto: futureProto,
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID:     1,
					ApprovalProgram:   v5,
					ClearStateProgram: v5,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
					ExtraProgramPages: 1,
					OnCompletion:      UpdateApplicationOC,
				},
			},
			proto:         protoV28,
			expectedError: fmt.Errorf("tx.ExtraProgramPages is immutable"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					Boxes:         []BoxRef{{Index: 1, Name: []byte("junk")}},
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.Boxes[0].Index is 1. Exceeds len(tx.ForeignApps)"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					Boxes:         []BoxRef{{Index: 1, Name: []byte("junk")}},
					ForeignApps:   []basics.AppIndex{1},
				},
			},
			proto: futureProto,
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					Boxes:         []BoxRef{{Index: 1, Name: []byte("junk")}},
					ForeignApps:   []basics.AppIndex{1},
				},
			},
			proto:         protoV32,
			expectedError: fmt.Errorf("tx.Boxes too long, max number of box references is 0"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					Boxes:         []BoxRef{{Index: 1, Name: make([]byte, 65)}},
					ForeignApps:   []basics.AppIndex{1},
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.Boxes[0].Name too long, max len 64 bytes"),
		},
		{
			tx: Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: okHeader,
				ApplicationCallTxnFields: ApplicationCallTxnFields{
					ApplicationID: 1,
					Boxes:         []BoxRef{{Index: 1, Name: make([]byte, 65)}},
					ForeignApps:   []basics.AppIndex{1},
				},
			},
			proto:         protoV36,
			expectedError: nil,
		},
	}
	for _, usecase := range usecases {
		err := usecase.tx.WellFormed(SpecialAddresses{}, usecase.proto)
		assert.Equal(t, usecase.expectedError, err)
	}
}
