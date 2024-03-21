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
	"strings"

	"gopkg.in/yaml.v3"
)

// ---- types ----

// TxTypeID is the transaction type.
type TxTypeID string

const (
	genesis TxTypeID = "genesis"

	// TX Distribution / ID's
	paymentTx     TxTypeID = "pay"
	assetTx       TxTypeID = "asset"
	applicationTx TxTypeID = "appl"
	//keyRegistrationTx TxTypeID = "keyreg"

	// Payment TX Distribution / ID's
	paymentAcctCreateTx TxTypeID = "pay_create"
	paymentPayTx        TxTypeID = "pay_pay"

	// Asset TX Distribution / ID's
	assetCreate  TxTypeID = "asset_create"
	assetDestroy TxTypeID = "asset_destroy"
	assetOptin   TxTypeID = "asset_optin"
	assetXfer    TxTypeID = "asset_xfer"
	assetClose   TxTypeID = "asset_close"

	// App kind TX Distribution / ID's don't exist because these are flattened
	// into weights across (app kinds) X (app tx type)

	// App Swap TX Distribution / ID's
	appSwapCreate TxTypeID = "app_swap_create"
	appSwapUpdate TxTypeID = "app_swap_update"
	appSwapDelete TxTypeID = "app_swap_delete"
	appSwapOptin  TxTypeID = "app_swap_optin"
	appSwapCall   TxTypeID = "app_swap_call"
	appSwapClose  TxTypeID = "app_swap_close"
	appSwapClear  TxTypeID = "app_swap_clear"

	// App Boxes TX Distribution / ID's
	appBoxesCreate TxTypeID = "app_boxes_create"
	appBoxesUpdate TxTypeID = "app_boxes_update"
	appBoxesDelete TxTypeID = "app_boxes_delete"
	appBoxesOptin  TxTypeID = "app_boxes_optin"
	appBoxesCall   TxTypeID = "app_boxes_call"
	appBoxesClose  TxTypeID = "app_boxes_close"
	appBoxesClear  TxTypeID = "app_boxes_clear"

	// For reporting side-effects of higher level transactions
	effectPaymentTxSibling = "effect_payment_sibling"
	effectInnerTx          = "effect_inner_tx"

	// Defaults
	defaultGenesisAccountsCount         uint64 = 1000
	defaultGenesisAccountInitialBalance uint64 = 1_000_000_000000 // 1 million algos per account

	assetTotal uint64 = 100_000_000_000_000_000 // 100 billion units per asset

	consensusTimeMilli int64 = 3300
)

type appKind uint8

const (
	appKindSwap appKind = iota
	appKindBoxes
)

func (a appKind) String() string {
	switch a {
	case appKindSwap:
		return "swap"
	case appKindBoxes:
		return "boxes"
	default:
		// Return a default value for unknown kinds.
		return "Unknown"
	}
}

type appTxType uint8

const (
	appTxTypeCreate appTxType = iota
	appTxTypeUpdate
	appTxTypeDelete
	appTxTypeOptin
	appTxTypeCall
	appTxTypeClose
	appTxTypeClear
)

func (a appTxType) String() string {
	switch a {
	case appTxTypeCreate:
		return "create"
	case appTxTypeUpdate:
		return "update"
	case appTxTypeDelete:
		return "delete"
	case appTxTypeOptin:
		return "optin"
	case appTxTypeCall:
		return "call"
	case appTxTypeClose:
		return "close"
	case appTxTypeClear:
		return "clear"
	default:
		// Return a default value for unknown types.
		return "Unknown"
	}
}

func parseAppTxType(txType TxTypeID) (isApp bool, kind appKind, tx appTxType, err error) {
	parts := strings.Split(string(txType), "_")

	if len(parts) != 3 {
		err = fmt.Errorf("invalid tx type for parsing")
		return
	}

	if len(parts) > 1 && strings.HasPrefix(parts[0], "app") {
		isApp = true
		// Setting the app kind
		switch parts[1] {
		case "swap":
			kind = appKindSwap
		case "boxes":
			kind = appKindBoxes
		default:
			err = fmt.Errorf("invalid app kind")
			return
		}

		switch parts[2] {
		case "create":
			tx = appTxTypeCreate
		case "update":
			tx = appTxTypeUpdate
		case "delete":
			tx = appTxTypeDelete
		case "optin":
			tx = appTxTypeOptin
		case "call":
			tx = appTxTypeCall
		case "close":
			tx = appTxTypeClose
		case "clear":
			tx = appTxTypeClear
		default:
			err = fmt.Errorf("invalid app tx type")
			return
		}
	} else {
		err = fmt.Errorf("not an app type")
		return
	}

	return
}

func getAppTxType(kind appKind, appType appTxType) TxTypeID {
	return TxTypeID(fmt.Sprintf("app_%s_%s", kind, appType))
}

// GenerationConfig defines the tunable parameters for block generation.
type GenerationConfig struct {
	Name                         string `yaml:"name"`
	NumGenesisAccounts           uint64 `yaml:"genesis_accounts"`
	GenesisAccountInitialBalance uint64 `yaml:"genesis_account_balance"`

	// Block generation
	TxnPerBlock uint64 `yaml:"tx_per_block"`

	// TX Distribution
	PaymentTransactionFraction float32 `yaml:"tx_pay_fraction"`
	AssetTransactionFraction   float32 `yaml:"tx_asset_fraction"`
	AppTransactionFraction     float32 `yaml:"tx_app_fraction"`

	// Payment TX Distribution
	PaymentNewAccountFraction float32 `yaml:"pay_acct_create_fraction"`
	PaymentFraction           float32 `yaml:"pay_xfer_fraction"`

	// Asset TX Distribution
	AssetCreateFraction  float32 `yaml:"asset_create_fraction"`
	AssetDestroyFraction float32 `yaml:"asset_destroy_fraction"`
	AssetOptinFraction   float32 `yaml:"asset_optin_fraction"`
	AssetXferFraction    float32 `yaml:"asset_xfer_fraction"`
	AssetCloseFraction   float32 `yaml:"asset_close_fraction"`

	// App kind TX Distribution
	AppSwapFraction  float32 `yaml:"app_swap_fraction"`
	AppBoxesFraction float32 `yaml:"app_boxes_fraction"`

	// App Swap TX Distribution
	AppSwapCreateFraction float32 `yaml:"app_swap_create_fraction"`
	AppSwapUpdateFraction float32 `yaml:"app_swap_update_fraction"`
	AppSwapDeleteFraction float32 `yaml:"app_swap_delete_fraction"`
	AppSwapOptinFraction  float32 `yaml:"app_swap_optin_fraction"`
	AppSwapCallFraction   float32 `yaml:"app_swap_call_fraction"`
	AppSwapCloseFraction  float32 `yaml:"app_swap_close_fraction"`
	AppSwapClearFraction  float32 `yaml:"app_swap_clear_fraction"`

	// App Boxes TX Distribution
	AppBoxesCreateFraction float32 `yaml:"app_boxes_create_fraction"`
	AppBoxesUpdateFraction float32 `yaml:"app_boxes_update_fraction"`
	AppBoxesDeleteFraction float32 `yaml:"app_boxes_delete_fraction"`
	AppBoxesOptinFraction  float32 `yaml:"app_boxes_optin_fraction"`
	AppBoxesCallFraction   float32 `yaml:"app_boxes_call_fraction"`
	AppBoxesCloseFraction  float32 `yaml:"app_boxes_close_fraction"`
	AppBoxesClearFraction  float32 `yaml:"app_boxes_clear_fraction"`
}

// ---- construction and validation ----

// initializeConfigFile reads the config file and validates its parameters. Certain missing
// parameters are defaulted to a reasonable value when missing, or when an entire associated
// group is missing.
func initializeConfigFile(configFile string) (config GenerationConfig, err error) {
	var data []byte
	data, err = os.ReadFile(configFile)
	if err != nil {
		return
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return
	}

	err = config.validateWithDefaults(true)
	return
}

// validateWithDefaults validates the config parameters. When defaults is true
// certain missing parameters are defaulted to reasonable values.
// When defaults is false, validate only without attempting to set defaults.
func (cfg *GenerationConfig) validateWithDefaults(defaults bool) error {
	if cfg.Name == "" {
		return fmt.Errorf("scenario name must be set")
	}

	if cfg.NumGenesisAccounts == 0 {
		if defaults {
			cfg.NumGenesisAccounts = defaultGenesisAccountsCount
		} else {
			return fmt.Errorf("number of genesis accounts must be > 0")
		}
	}

	if cfg.GenesisAccountInitialBalance == 0 {
		if defaults {
			cfg.GenesisAccountInitialBalance = defaultGenesisAccountInitialBalance
		} else {
			return fmt.Errorf("genesis account initial balance must be > 0")
		}
	}

	var weights []*float32

	weights = []*float32{&cfg.PaymentTransactionFraction, &cfg.AssetTransactionFraction, &cfg.AppTransactionFraction}
	if eTxnTypes := sumIsCloseToOneWithDefault(defaults, weights...); eTxnTypes != nil {
		return fmt.Errorf("transaction distribution ratios sum should equal 1: %w", eTxnTypes)
	}

	weights = []*float32{&cfg.PaymentNewAccountFraction, &cfg.PaymentFraction}
	if ePymtTypes := sumIsCloseToOneWithDefault(defaults, weights...); ePymtTypes != nil {
		return fmt.Errorf("payment configuration ratios sum should equal 1: %w", ePymtTypes)
	}

	weights = []*float32{&cfg.AssetCreateFraction, &cfg.AssetDestroyFraction, &cfg.AssetOptinFraction, &cfg.AssetCloseFraction, &cfg.AssetXferFraction}
	if eAssetTypes := sumIsCloseToOneWithDefault(defaults, weights...); eAssetTypes != nil {
		return fmt.Errorf("asset configuration ratios sum should equal 1: %w", eAssetTypes)
	}

	weights = []*float32{&cfg.AppSwapFraction, &cfg.AppBoxesFraction}
	if eAppTypes := sumIsCloseToOneWithDefault(defaults, weights...); eAppTypes != nil {
		return fmt.Errorf("app configuration ratios sum should equal 1: %w", eAppTypes)
	}

	weights = []*float32{&cfg.AppSwapCreateFraction, &cfg.AppSwapUpdateFraction, &cfg.AppSwapDeleteFraction, &cfg.AppSwapOptinFraction, &cfg.AppSwapCallFraction, &cfg.AppSwapCloseFraction, &cfg.AppSwapClearFraction}
	if eAppSwapTypes := sumIsCloseToOneWithDefault(defaults, weights...); eAppSwapTypes != nil {
		return fmt.Errorf("app swap configuration ratios sum should equal 1: %w", eAppSwapTypes)
	}

	weights = []*float32{&cfg.AppBoxesCreateFraction, &cfg.AppBoxesUpdateFraction, &cfg.AppBoxesDeleteFraction, &cfg.AppBoxesOptinFraction, &cfg.AppBoxesCallFraction, &cfg.AppBoxesCloseFraction, &cfg.AppBoxesClearFraction}
	if eAppBoxesTypes := sumIsCloseToOneWithDefault(defaults, weights...); eAppBoxesTypes != nil {
		return fmt.Errorf("app boxes configuration ratios sum should equal 1: %w", eAppBoxesTypes)

	}

	return nil
}

func asPtrSlice(weights []float32) []*float32 {
	ptrs := make([]*float32, len(weights))
	for i := range weights {
		weight := weights[i]
		ptrs[i] = &weight
	}
	return ptrs
}

// sumIsCloseToOneWithDefault returns no error if the sum of the params is close to 1.
// It returns an error if any of the params are negative.
// Finally, in the case that all the params are zero, it sets the first param to 1 and returns no error.
func sumIsCloseToOneWithDefault(defaults bool, params ...*float32) error {
	if len(params) == 0 {
		return fmt.Errorf("no params provided")
	}

	sum, valid, err := validateSumCloseToOne(params)
	if valid || err != nil {
		return err
	}

	if sum == 0 && defaults {
		*params[0] = 1
		return nil
	}

	return fmt.Errorf("sum of params is not close to 1: %f", sum)
}

// validateSumCloseToOne returns the sum of the params, whether the sum is close to 1, and any error encountered.
// In the case that err is not nil, the value of valid is undefined.
func validateSumCloseToOne(params []*float32) (sum float32, valid bool, err error) {
	for i, num := range params {
		if *num < 0 {
			return *num, false, fmt.Errorf("param at index %d is negative: %f", i, *num)
		}
		sum += *num
	}
	if 0.99 < sum && sum < 1.01 {
		return sum, true, nil
	}
	return sum, false, nil
}
