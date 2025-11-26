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

package main

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name                                       string
	xPkg, xBranch, xType, yPkg, yBranch, yType string
	skip                                       bool
	skipReason                                 string
}

func TestCrossRepoTypes(t *testing.T) {
	// NOTE: the heavy lifting is done by the first test case, so it's better to apply PartitionTest to the
	// entire test as opposed to partitioning each test case.
	partitiontest.PartitionTest(t)

	testCases := []testCase{
		{
			name:    "SDK: StateDelta",
			xPkg:    "github.com/algorand/go-algorand/ledger/ledgercore",
			xBranch: "",
			xType:   "StateDelta",
			yPkg:    "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch: "main",
			yType:   "LedgerStateDelta",
		},
		{
			name:       "goal-v-sdk-genesis",
			xPkg:       "github.com/algorand/go-algorand/data/bookkeeping",
			xType:      "Genesis",
			yPkg:       "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch:    "main",
			yType:      "Genesis",
			skip:       true,
			skipReason: `LEVEL 3 of goal basics.AccountData has 12 fields missing from SDK types.Account`,
		},
		{
			name:       "goal-v-sdk-block",
			xPkg:       "github.com/algorand/go-algorand/data/bookkeeping",
			xType:      "Block",
			yPkg:       "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch:    "main",
			yType:      "Block",
			skip:       true,
			skipReason: `Several issues. For example: LEVEL 5 of goal bookkeeping.Block is EvalDelta with field [SharedAccts](codec:"sa,allocbound=bounds.MaxEvalDeltaAccounts") VS SDK types.EvalDelta is missing SharedAccts field`,
		},
		{
			name:    "goal-v-sdk-eval-delta",
			xPkg:    "github.com/algorand/go-algorand/data/transactions",
			xType:   "EvalDelta",
			yPkg:    "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch: "main",
			yType:   "EvalDelta",
		},
		{
			name:    "goal-v-sdk-consensus",
			xPkg:    "github.com/algorand/go-algorand/config",
			xType:   "ConsensusParams",
			yPkg:    "github.com/algorand/go-algorand-sdk/v2/protocol/config",
			yBranch: "main",
			yType:   "ConsensusParams",
		},
		{
			name:    "goal-v-sdk-blockheader",
			xPkg:    "github.com/algorand/go-algorand/data/bookkeeping",
			xType:   "BlockHeader",
			yPkg:    "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch: "main",
			yType:   "BlockHeader",
		},
		{
			name:    "goal-v-sdk-stateproof",
			xPkg:    "github.com/algorand/go-algorand/crypto/stateproof",
			xType:   "StateProof",
			yPkg:    "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch: "main",
			yType:   "StateProof",
		},
		{
			name:  "goal-v-spv-stateproof",
			xPkg:  "github.com/algorand/go-algorand/crypto/stateproof",
			xType: "StateProof",
			yPkg:  "github.com/algorand/go-stateproof-verification/stateproof",
			yType: "StateProof",
		},
	}

	for _, tc := range testCases {
		// These should be run in serial as they modify go.mod, go.sum and typeAnalyzer/main.go
		// TODO: it probably is preferrable to setup and `go get` everything _before_ running the tests
		// and tearDown after the tests are done.
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip {
				t.Skip(tc.skipReason)
			}
			err := runApp(tc.xPkg, tc.xBranch, tc.xType, tc.yPkg, tc.yBranch, tc.yType, "")
			require.NoError(t, err)
		})
	}
}
