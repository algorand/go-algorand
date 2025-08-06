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
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestResourceRefEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	assert.True(t, ResourceRef{}.Empty())
	for _, nz := range basics_testing.NearZeros(t, ResourceRef{}) {
		rr := nz.(ResourceRef)
		assert.False(t, rr.Empty(), "Empty is disregarding a non-zero field in %+v", rr)
	}
}

func TestApplicationCallFieldsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := assert.New(t)

	ac := ApplicationCallTxnFields{}
	a.True(ac.Empty())

	for _, nz := range basics_testing.NearZeros(t, ac) {
		fields := nz.(ApplicationCallTxnFields)
		a.False(fields.Empty(), "Empty is disregarding a non-zero field in %+v", fields)
	}
}

func TestEncodedAppTxnAllocationBounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
		if proto.MaxAppAccess > encodedMaxAccess {
			require.Failf(t, "proto.MaxAppAccess > encodedMaxAccess", "protocol version = %s", protoVer)
		}
	}
}

func TestAppCallAccessWellFormed(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	preAccessCV := protocol.ConsensusV40
	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	cases := []struct {
		expectedError string
		cv            protocol.ConsensusVersion // defaults to future if not set
		ac            ApplicationCallTxnFields
	}{
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        slices.Repeat([]ResourceRef{{}}, 16),
			},
		},
		{
			expectedError: "tx.Access too long, max number of references is 0",
			cv:            preAccessCV,
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{}},
			},
		},
		{
			expectedError: "tx.Access too long, max number of references is 16",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        slices.Repeat([]ResourceRef{{}}, 17),
			},
		},
		{
			expectedError: "tx.Accounts can't be used when tx.Access is used",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{}},
				Accounts:      []basics.Address{addr1},
			},
		},
		{
			expectedError: "tx.ForeignAssets can't be used when tx.Access is used",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{}},
				ForeignAssets: []basics.AssetIndex{2},
			},
		},
		{
			expectedError: "tx.ForeignApps can't be used when tx.Access is used",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{}},
				ForeignApps:   []basics.AppIndex{3},
			},
		},
		{
			expectedError: "tx.Boxes can't be used when tx.Access is used",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{}},
				Boxes:         []BoxRef{{Index: 0}},
			},
		},

		// Exercise holdings
		{
			expectedError: "holding Asset reference 2 outside tx.Access",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Holding: HoldingRef{Asset: 2}}},
			},
		},
		{
			expectedError: "holding Asset reference 1 is not an Asset",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Holding: HoldingRef{Asset: 1}}},
			},
		},
		{
			expectedError: "holding Asset reference 0 outside tx.Access",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access: []ResourceRef{
					{Address: basics.Address{0xaa}},
					{Holding: HoldingRef{Address: 1}},
				},
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access: []ResourceRef{
					{Address: basics.Address{0xaa}},
					{Asset: 99},
					{Holding: HoldingRef{Address: 1, Asset: 2}},
				},
			},
		},

		// Exercise locals
		{
			expectedError: "locals App reference 2 outside tx.Access",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Locals: LocalsRef{App: 2}}},
			},
		},
		{
			expectedError: "locals App reference 1 is not an App",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Locals: LocalsRef{App: 1}}},
			},
		},
		{
			expectedError: "locals App reference 0 outside tx.Access",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access: []ResourceRef{
					{Address: basics.Address{0xaa}},
					{Locals: LocalsRef{Address: 1}},
				},
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access: []ResourceRef{
					{Address: basics.Address{0xaa}},
					{App: 99},
					{Locals: LocalsRef{Address: 1, App: 2}},
				},
			},
		},

		// Exercise boxes
		{
			expectedError: "box Index 2 outside tx.Access",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Box: BoxRef{Index: 2}}},
			},
		},
		{
			expectedError: "box Index reference 1 is not an App",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Box: BoxRef{Index: 1}}},
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{App: 20}, {Box: BoxRef{Index: 1}}},
			},
		},
		{
			expectedError: "tx.Access box Name too long, max len 64 bytes",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Box: BoxRef{Name: make([]byte, 65)}}},
			},
		},

		// Multiple uses in ResourceRef
		{
			expectedError: "tx.Access element has fields from multiple types",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Address: basics.Address{0x01}, Box: BoxRef{Name: []byte("a")}}},
			},
		},
		{
			expectedError: "tx.Access element has fields from multiple types",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{App: 10, Locals: LocalsRef{App: 1}}},
			},
		},
		{
			expectedError: "tx.Access element has fields from multiple types",
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Access:        []ResourceRef{{Asset: 10, Holding: HoldingRef{Asset: 1}}},
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
	t.Parallel()

	v5 := []byte{0x05}
	v6 := []byte{0x06}
	cases := []struct {
		expectedError string
		cv            protocol.ConsensusVersion // defaults to future if not set
		ac            ApplicationCallTxnFields
	}{
		{
			ac: ApplicationCallTxnFields{
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				ExtraProgramPages: 0,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				ExtraProgramPages: 3,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
			},
		},
		{
			expectedError: "program version mismatch",
			ac: ApplicationCallTxnFields{
				ApprovalProgram:   v5,
				ClearStateProgram: v6,
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
			// test the same thing for update, unless test has epp, which is illegal in update
			if tc.ac.ExtraProgramPages != 0 {
				return
			}
			tc.ac.OnCompletion = UpdateApplicationOC
			tc.ac.ApplicationID = 1
			err = tc.ac.wellFormed(config.Consensus[cv])
			if tc.expectedError != "" {
				require.ErrorContains(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWellFormedErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cv27 := protocol.ConsensusV27
	cv28 := protocol.ConsensusV28
	cv32 := protocol.ConsensusV32
	cv36 := protocol.ConsensusV36

	v5 := []byte{0x05}
	cases := []struct {
		ac            ApplicationCallTxnFields
		cv            protocol.ConsensusVersion
		expectedError string
	}{
		{
			expectedError: "invalid application OnCompletion (6)",
			ac: ApplicationCallTxnFields{
				ApplicationID: 99,
				OnCompletion:  DeleteApplicationOC + 1,
			},
		},
		{
			expectedError: "programs may only be specified during application creation or update",
			ac: ApplicationCallTxnFields{
				ApplicationID:     99,
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				OnCompletion:      NoOpOC,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     99,
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				OnCompletion:      UpdateApplicationOC,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     0, // creation
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				ExtraProgramPages: 1,
			},
			cv:            cv27,
			expectedError: "tx.ExtraProgramPages exceeds MaxExtraAppProgramPages = 0",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     0, // creation
				ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
				ClearStateProgram: []byte("Xjunk"),
			},
			cv:            cv27,
			expectedError: "approval program too long. max len 1024 bytes",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     0, // creation
				ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
				ClearStateProgram: []byte("Xjunk"),
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     0, // creation
				ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
				ClearStateProgram: []byte(strings.Repeat("X", 1025)),
			},
			expectedError: "app programs too long. max total len 2048 bytes",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     0, // creation
				ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
				ClearStateProgram: []byte(strings.Repeat("X", 1025)),
				ExtraProgramPages: 1,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				GlobalStateSchema: basics.StateSchema{NumByteSlice: 1},
			},
			expectedError: "tx.GlobalStateSchema is immutable",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				LocalStateSchema: basics.StateSchema{NumUint: 1},
			},
			expectedError: "tx.LocalStateSchema is immutable",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     0,
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				GlobalStateSchema: basics.StateSchema{NumByteSlice: 30, NumUint: 35},
			},
			expectedError: "tx.GlobalStateSchema is too large. 65 > 64",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     0,
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				LocalStateSchema: basics.StateSchema{NumUint: 17},
			},
			expectedError: "tx.LocalStateSchema is too large. 17 > 16",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				ExtraProgramPages: 1,
			},
			expectedError: "tx.ExtraProgramPages is immutable",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     0,
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				ExtraProgramPages: 4,
			},
			expectedError: "tx.ExtraProgramPages exceeds MaxExtraAppProgramPages = 3",
			cv:            cv28,
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     1,
				ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
				ClearStateProgram: []byte(strings.Repeat("X", 1025)),
				ExtraProgramPages: 0,
				OnCompletion:      UpdateApplicationOC,
			},
			cv: protocol.ConsensusFuture,
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:   1,
				ApplicationArgs: slices.Repeat([][]byte{[]byte("arg")}, 16),
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:   1,
				ApplicationArgs: slices.Repeat([][]byte{[]byte("arg")}, 17),
			},
			expectedError: "tx.ApplicationArgs has too many arguments. 17 > 16",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:   1,
				ApplicationArgs: [][]byte{make([]byte, 1500), make([]byte, 548)},
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:   1,
				ApplicationArgs: [][]byte{make([]byte, 1501), make([]byte, 548)},
			},
			expectedError: "tx.ApplicationArgs total length is too long. 2049 > 2048",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				ForeignApps:   []basics.AppIndex{10, 11},
			},
			cv: cv27,
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				ForeignApps:   []basics.AppIndex{10, 11, 12},
			},
			cv:            cv27,
			expectedError: "tx.ForeignApps too long, max number of foreign apps is 2",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				ForeignApps:   []basics.AppIndex{10, 11, 12, 13, 14, 15, 16, 17},
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Accounts:      slices.Repeat([]basics.Address{{}}, 4),
			},
			cv: protocol.ConsensusV40,
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Accounts:      slices.Repeat([]basics.Address{{}}, 5),
			},
			cv:            protocol.ConsensusV40,
			expectedError: "tx.Accounts too long, max number of accounts is 4",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Accounts:      slices.Repeat([]basics.Address{{}}, 9),
			},
			expectedError: "tx.Accounts too long, max number of accounts is 8",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				ForeignAssets: []basics.AssetIndex{14, 15, 16, 17, 18, 19, 20, 21, 22},
			},
			expectedError: "tx.ForeignAssets too long, max number of foreign assets is 8",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Accounts:      []basics.Address{{}, {}, {}},
				ForeignApps:   []basics.AppIndex{14, 15, 16, 17},
				ForeignAssets: []basics.AssetIndex{14, 15, 16, 17},
			},
			expectedError: "tx references exceed MaxAppTotalTxnReferences = 8",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     1,
				ApprovalProgram:   []byte(strings.Repeat("X", 1025)),
				ClearStateProgram: []byte(strings.Repeat("X", 1025)),
				ExtraProgramPages: 0,
				OnCompletion:      UpdateApplicationOC,
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID:     1,
				ApprovalProgram:   v5,
				ClearStateProgram: v5,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
				ExtraProgramPages: 1,
				OnCompletion:      UpdateApplicationOC,
			},
			cv:            cv28,
			expectedError: "tx.ExtraProgramPages is immutable",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Boxes:         []BoxRef{{Index: 1, Name: []byte("junk")}},
			},
			expectedError: "tx.Boxes[0].Index is 1. Exceeds len(tx.ForeignApps)",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Boxes:         []BoxRef{{Index: 1, Name: []byte("junk")}},
				ForeignApps:   []basics.AppIndex{1},
			},
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Boxes:         []BoxRef{{Index: 1, Name: []byte("junk")}},
				ForeignApps:   []basics.AppIndex{1},
			},
			cv:            cv32,
			expectedError: "tx.Boxes too long, max number of box references is 0",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Boxes:         []BoxRef{{Index: 1, Name: make([]byte, 65)}},
				ForeignApps:   []basics.AppIndex{1},
			},
			expectedError: "tx.Boxes[0].Name too long, max len 64 bytes",
		},
		{
			ac: ApplicationCallTxnFields{
				ApplicationID: 1,
				Boxes:         []BoxRef{{Index: 1, Name: make([]byte, 65)}},
				ForeignApps:   []basics.AppIndex{1},
			},
			cv: cv36,
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
