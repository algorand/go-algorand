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

package transactions

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLogicSigBlankAndHasProgram(t *testing.T) {
	partitiontest.PartitionTest(t)

	nonblankSig := crypto.Signature{}
	nonblankSig[0] = 1

	pqFixture := makePQSigTestFixture(t, 13)

	tests := []struct {
		name       string
		lsig       LogicSig
		blank      bool
		hasProgram bool
	}{
		{
			name:  "zero value",
			blank: true,
		},
		{
			name:       "program",
			lsig:       LogicSig{Logic: []byte{1}},
			hasProgram: true,
		},
		{
			name: "args",
			lsig: LogicSig{Args: [][]byte{{}}},
		},
		{
			name: "signature",
			lsig: LogicSig{Sig: nonblankSig},
		},
		{
			name: "multisig",
			lsig: LogicSig{Msig: crypto.MultisigSig{Version: 1}},
		},
		{
			name: "logic multisig",
			lsig: LogicSig{LMsig: crypto.MultisigSig{Version: 1}},
		},
		{
			name: "pqsig",
			lsig: LogicSig{PQsig: pqFixture.pqSig},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.blank, test.lsig.Blank())
			require.Equal(t, test.hasProgram, test.lsig.HasProgram())
		})
	}
}

func TestLogicSigPQSigMsgpackRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 11)
	lsig := LogicSig{
		Logic: []byte{1, 32, 1},
		Args:  [][]byte{{2, 3}},
		PQsig: fixture.pqSig,
	}

	var decoded LogicSig
	left, err := decoded.UnmarshalMsg(lsig.MarshalMsg(nil))
	require.NoError(t, err)
	require.Empty(t, left)
	require.True(t, lsig.Equal(&decoded))
}

func TestLogicSigBlankPQSigOmitted(t *testing.T) {
	partitiontest.PartitionTest(t)

	lsig := LogicSig{Logic: []byte{1}}
	bts := lsig.MarshalMsg(nil)
	fields, isNil, bts, err := msgp.ReadMapHeaderBytes(bts)
	require.NoError(t, err)
	require.False(t, isNil)

	for ; fields > 0; fields-- {
		var field []byte
		field, bts, err = msgp.ReadMapKeyZC(bts)
		require.NoError(t, err)
		require.NotEqual(t, "pqsig", string(field))

		bts, err = msgp.Skip(bts)
		require.NoError(t, err)
	}
	require.Empty(t, bts)
}
