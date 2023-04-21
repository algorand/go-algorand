package main

import (
	"testing"
)

type testCase struct {
	name                                       string
	xPkg, xBranch, xType, yPkg, yBranch, yType string
	expectedErr                                error
	skip                                       bool
	skipReason                                 string
}

func TestRunApp(t *testing.T) {
	testCases := []testCase{
		{
			name:        "SDK: StateDelta",
			xPkg:        "github.com/algorand/go-algorand/ledger/ledgercore",
			xBranch:     "",
			xType:       "StateDelta",
			yPkg:        "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch:     "develop",
			yType:       "LedgerStateDelta",
			expectedErr: nil,
		},
		{
			name:        "goal-v-sdk-genesis",
			xPkg:        "github.com/algorand/go-algorand/data/bookkeeping",
			xType:       "Genesis",
			yPkg:        "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch:     "develop",
			yType:       "Genesis",
			expectedErr: nil,
			skip:        true,
			skipReason:  `LEVEL 3 goal basics.AccountData has 12 fields missing from SDK types.Account`,
		},
		{
			name:        "goal-v-sdk-block",
			xPkg:        "github.com/algorand/go-algorand/data/bookkeeping",
			xType:       "Block",
			yPkg:        "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch:     "develop",
			yType:       "Block",
			expectedErr: nil,
			skip:        true,
			skipReason:  `LEVEL 3 goal transactions.EvalDelta has [SharedAccts](codec:"sa,allocbound=config.MaxEvalDeltaAccounts") VS SDK types.EvalDelta missing`,
		},
		{
			name:        "goal-v-sdk-blockheader",
			xPkg:        "github.com/algorand/go-algorand/data/bookkeeping",
			xType:       "BlockHeader",
			yPkg:        "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch:     "develop",
			yType:       "BlockHeader",
			expectedErr: nil,
		},
		{
			name:        "goal-v-sdk-stateproof",
			xPkg:        "github.com/algorand/go-algorand/crypto/stateproof",
			xType:       "StateProof",
			yPkg:        "github.com/algorand/go-algorand-sdk/v2/types",
			yBranch:     "develop",
			yType:       "StateProof",
			expectedErr: nil,
		},
		{
			name:        "goal-v-spv-stateproof",
			xPkg:        "github.com/algorand/go-algorand/crypto/stateproof",
			xType:       "StateProof",
			yPkg:        "github.com/algorand/go-stateproof-verification/stateproof",
			yType:       "StateProof",
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		// These should be run in serial as they modify typeAnalyzer/main.go
		// TODO: it probably is preferrable to `go get` everything _before_ running the tests.
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip {
				t.Skip(tc.skipReason)
			}
			err := runApp(tc.xPkg, tc.xBranch, tc.xType, tc.yPkg, tc.yBranch, tc.yType)
			if err != tc.expectedErr {
				t.Errorf("Expected error: %v, got: %v", tc.expectedErr, err)
			}
		})
	}
}
