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

package generator

import (
	"fmt"
	"os"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestInitConfigFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	config, err := initializeConfigFile("test_scenario.yml")
	require.NoError(t, err)
	require.Equal(t, uint64(10), config.NumGenesisAccounts)
	require.Equal(t, float32(0.25), config.AssetCloseFraction)
	require.Equal(t, float32(0.0), config.AssetDestroyFraction)
}

func TestInitConfigFileNotExist(t *testing.T) {
	partitiontest.PartitionTest(t)
	_, err := initializeConfigFile("this_is_not_a_config_file")

	if _, ok := err.(*os.PathError); !ok {
		require.Fail(t, "This should generate a path error")
	}
}

func TestValidateWithDefaults(t *testing.T) {
	partitiontest.PartitionTest(t)

	empty := func(fs ...float32) bool {
		for _, f := range fs {
			if f != 0 {
				return false
			}
		}
		return true
	}

	sum := func(fs ...float32) float32 {
		s := float32(0)
		for _, f := range fs {
			s += f
		}
		return s
	}

	one := float32(1)

	testCases := []struct {
		name   string
		genCfg GenerationConfig
		err    error
	}{
		{
			name: "all fields valid",
			genCfg: GenerationConfig{
				Name:                         "Test",
				NumGenesisAccounts:           1,
				GenesisAccountInitialBalance: 1,
				TxnPerBlock:                  1,
			},
			err: nil,
		},
		{
			name:   "just a name",
			genCfg: GenerationConfig{Name: "Test"},
			err:    nil,
		},
		{
			name: "no name",
			genCfg: GenerationConfig{
				NumGenesisAccounts:           1,
				GenesisAccountInitialBalance: 1,
				TxnPerBlock:                  1,
			},
			err: fmt.Errorf("scenario name must be set"),
		},
		{
			name: "no genesis accounts",
			genCfg: GenerationConfig{
				Name:                         "Test",
				GenesisAccountInitialBalance: 1,
				TxnPerBlock:                  1,
			},
			err: nil,
		},
		{
			name: "no genesis account balance",
			genCfg: GenerationConfig{
				Name:               "Test",
				NumGenesisAccounts: 1,
			},
		},
		{
			name: "negative",
			genCfg: GenerationConfig{
				Name:                       "Test",
				NumGenesisAccounts:         1,
				PaymentTransactionFraction: -0.1,
			},
			err: fmt.Errorf("transaction distribution ratios sum should equal 1: param at index 0 is negative: -0.100000"),
		},
		{
			name: "doesn't sum to 1",
			genCfg: GenerationConfig{
				Name:                   "Test",
				NumGenesisAccounts:     1,
				AppBoxesCreateFraction: 0.5,
				AppBoxesUpdateFraction: 0.5,
				AppBoxesCallFraction:   0.5,
			},
			err: fmt.Errorf("app boxes configuration ratios sum should equal 1: sum of params is not close to 1: 1.500000"),
		},
		{
			name: "1-defaults",
			genCfg: GenerationConfig{
				Name:                         "Test",
				NumGenesisAccounts:           1,
				GenesisAccountInitialBalance: 42,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		cfg := tc.genCfg
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			emptyGenesisAccounts := cfg.NumGenesisAccounts == 0
			emptyGenesisAccountInitialBalance := cfg.GenesisAccountInitialBalance == 0
			emptyTxnDistributions := empty(cfg.PaymentTransactionFraction, cfg.AssetTransactionFraction, cfg.AppTransactionFraction)
			emptyPymtFractions := empty(cfg.PaymentNewAccountFraction, cfg.PaymentFraction)
			emptyAssetFractions := empty(cfg.AssetCreateFraction, cfg.AssetDestroyFraction, cfg.AssetOptinFraction, cfg.AssetCloseFraction, cfg.AssetXferFraction)
			emptyAppFractions := empty(cfg.AppSwapFraction, cfg.AppBoxesFraction)
			emptySwapFraction := empty(cfg.AppSwapCreateFraction, cfg.AppSwapUpdateFraction, cfg.AppSwapDeleteFraction, cfg.AppSwapOptinFraction, cfg.AppSwapCallFraction, cfg.AppSwapCloseFraction, cfg.AppSwapClearFraction)
			emptyBoxesFraction := empty(cfg.AppBoxesCreateFraction, cfg.AppBoxesUpdateFraction, cfg.AppBoxesDeleteFraction, cfg.AppBoxesOptinFraction, cfg.AppBoxesCallFraction, cfg.AppBoxesCloseFraction, cfg.AppBoxesClearFraction)

			err := cfg.validateWithDefaults(true)

			if tc.err == nil {
				require.Nil(t, err)
				require.Nil(t, cfg.validateWithDefaults(false))

				if emptyGenesisAccounts {
					require.Equal(t, defaultGenesisAccountsCount, cfg.NumGenesisAccounts)
				}

				if emptyGenesisAccountInitialBalance {
					require.Equal(t, defaultGenesisAccountInitialBalance, cfg.GenesisAccountInitialBalance)
				}

				if emptyTxnDistributions {
					require.Equal(t, one, cfg.PaymentTransactionFraction)
				}

				if emptyPymtFractions {
					require.Equal(t, one, cfg.PaymentNewAccountFraction)
				}

				if emptyAssetFractions {
					require.Equal(t, one, cfg.AssetCreateFraction)
				}

				if emptyAppFractions {
					require.Equal(t, one, cfg.AppSwapFraction)
				}

				if emptySwapFraction {
					require.Equal(t, one, cfg.AppSwapCreateFraction)
				}

				if emptyBoxesFraction {
					require.Equal(t, one, cfg.AppBoxesCreateFraction)
				}

				require.Equal(t, one, sum(cfg.PaymentTransactionFraction, cfg.AssetTransactionFraction, cfg.AppTransactionFraction))
				require.Equal(t, one, sum(cfg.PaymentNewAccountFraction, cfg.PaymentFraction))
				require.Equal(t, one, sum(cfg.AssetCreateFraction, cfg.AssetDestroyFraction, cfg.AssetOptinFraction, cfg.AssetCloseFraction, cfg.AssetXferFraction))
				require.Equal(t, one, sum(cfg.AppSwapFraction, cfg.AppBoxesFraction))
				require.Equal(t, one, sum(cfg.AppSwapCreateFraction, cfg.AppSwapUpdateFraction, cfg.AppSwapDeleteFraction, cfg.AppSwapOptinFraction, cfg.AppSwapCallFraction, cfg.AppSwapCloseFraction, cfg.AppSwapClearFraction))
				require.Equal(t, one, sum(cfg.AppBoxesCreateFraction, cfg.AppBoxesUpdateFraction, cfg.AppBoxesDeleteFraction, cfg.AppBoxesOptinFraction, cfg.AppBoxesCallFraction, cfg.AppBoxesCloseFraction, cfg.AppBoxesClearFraction))
			} else {
				require.Equal(t, tc.err.Error(), err.Error())
			}

		})
	}
}

func TestTxTypeParse(t *testing.T) {
	partitiontest.PartitionTest(t)
	tests := []struct {
		name   string
		txType TxTypeID
		IsApp  bool
		Kind   appKind
		TxType appTxType
		err    string
	}{
		{"App Swap Create", "app_swap_create", true, appKindSwap, appTxTypeCreate, ""},
		{"App Boxes Delete", "app_boxes_delete", true, appKindBoxes, appTxTypeDelete, ""},
		{"not enough _'s", "app_swap", false, 0, 0, "invalid app tx type for parsing"},
		{"too many _'s", "app_swap_delete_very_much", false, 0, 0, "invalid app tx type for parsing"},
		{"Invalid App Kind", "app_invalid_delete", false, 0, 0, "invalid app kind"},
		{"Invalid Tx Type", "app_boxes_invalid", false, 0, 0, "invalid app tx type"},
		{"Not An App", "not_an_app", false, 0, 0, "not an app type"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			isApp, kind, txType, err := parseAppTxType(test.txType)

			if test.err != "" {
				require.Error(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.IsApp, isApp, "Mismatch in isApp for %s", test.txType)
				require.Equal(t, test.Kind, kind, "Mismatch in kind for %s", test.txType)
				require.Equal(t, test.TxType, txType, "Mismatch in txType for %s", test.txType)
			}
		})
	}
}
