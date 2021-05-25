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
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
)

func TestApplicationCallFieldsNotChanged(t *testing.T) {
	af := ApplicationCallTxnFields{}
	s := reflect.ValueOf(&af).Elem()

	if s.NumField() != 11 {
		t.Errorf("You added or removed a field from transactions.ApplicationCallTxnFields. " +
			"Please ensure you have updated the Empty() method and then " +
			"fix this test")
	}
}

func TestApplicationCallFieldsEmpty(t *testing.T) {
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
	// ensure that all the supported protocols have value limits less or
	// equal to their corresponding codec allocbounds
	for protoVer, proto := range config.Consensus {
		if proto.MaxAppArgs > EncodedMaxApplicationArgs {
			require.Failf(t, "proto.MaxAppArgs > encodedMaxApplicationArgs", "protocol version = %s", protoVer)
		}
		if proto.MaxAppTxnAccounts > EncodedMaxAccounts {
			require.Failf(t, "proto.MaxAppTxnAccounts > encodedMaxAccounts", "protocol version = %s", protoVer)
		}
		if proto.MaxAppTxnForeignApps > EncodedMaxForeignApps {
			require.Failf(t, "proto.MaxAppTxnForeignApps > encodedMaxForeignApps", "protocol version = %s", protoVer)
		}
		if proto.MaxAppTxnForeignAssets > EncodedMaxForeignAssets {
			require.Failf(t, "proto.MaxAppTxnForeignAssets > encodedMaxForeignAssets", "protocol version = %s", protoVer)
		}
	}
}
