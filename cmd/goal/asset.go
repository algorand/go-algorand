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
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"
)

var (
	assetID                 basics.AssetIndex
	assetCreator            string
	assetTotal              uint64
	assetDecimals           uint32
	assetFrozen             bool
	assetUnitName           string
	assetMetadataHashBase64 string
	assetURL                string
	assetName               string
	assetManager            string
	assetReserve            string
	assetClawback           string
	assetFreezer            string
	assetNoManager          bool
	assetNoReserve          bool
	assetNoFreezer          bool
	assetNoClawback         bool

	assetNewManager  string
	assetNewReserve  string
	assetNewFreezer  string
	assetNewClawback string
)

func init() {
	assetCmd.AddCommand(createAssetCmd)
	assetCmd.AddCommand(destroyAssetCmd)
	assetCmd.AddCommand(configAssetCmd)
	assetCmd.AddCommand(sendAssetCmd)
	assetCmd.AddCommand(infoAssetCmd)
	assetCmd.AddCommand(freezeAssetCmd)
	assetCmd.AddCommand(optinAssetCmd)

	assetCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")

	createAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for creating an asset")
	createAssetCmd.Flags().Uint64Var(&assetTotal, "total", 0, "Total amount of tokens for created asset")
	createAssetCmd.Flags().Uint32Var(&assetDecimals, "decimals", 0, "The number of digits to use after the decimal point when displaying this asset. If set to 0, the asset is not divisible beyond its base unit. If set to 1, the base asset unit is tenths. If 2, the base asset unit is hundredths, and so on.")
	createAssetCmd.Flags().BoolVar(&assetFrozen, "defaultfrozen", false, "Freeze or not freeze holdings by default")
	createAssetCmd.Flags().StringVar(&assetUnitName, "unitname", "", "Name for the unit of asset")
	createAssetCmd.Flags().StringVar(&assetName, "name", "", "Name for the entire asset")
	createAssetCmd.Flags().StringVar(&assetURL, "asseturl", "", "URL where user can access more information about the asset (max 32 bytes)")
	createAssetCmd.Flags().StringVar(&assetMetadataHashBase64, "assetmetadatab64", "", "base-64 encoded 32-byte commitment to asset metadata")
	createAssetCmd.Flags().StringVar(&assetManager, "manager", "", "Manager account that can issue transactions to re-configure or destroy the asset")
	createAssetCmd.Flags().StringVar(&assetReserve, "reserve", "", "Reserve account that non-minted assets will reside in")
	createAssetCmd.Flags().StringVar(&assetFreezer, "freezer", "", "Freezer account that can freeze or unfreeze the asset holdings for a specific account")
	createAssetCmd.Flags().StringVar(&assetClawback, "clawback", "", "Clawback account that is allowed to transfer assets from and to any asset holder")
	createAssetCmd.Flags().BoolVar(&assetNoManager, "no-manager", false, "Explicitly declare the lack of manager")
	createAssetCmd.Flags().BoolVar(&assetNoReserve, "no-reserve", false, "Explicitly declare the lack of reserve")
	createAssetCmd.Flags().BoolVar(&assetNoFreezer, "no-freezer", false, "Explicitly declare the lack of freezer")
	createAssetCmd.Flags().BoolVar(&assetNoClawback, "no-clawback", false, "Explicitly declare the lack of clawback")
	createAssetCmd.MarkFlagRequired("total")
	createAssetCmd.MarkFlagRequired("creator")

	destroyAssetCmd.Flags().StringVar(&assetManager, "manager", "", "Manager account to issue the destroy transaction (defaults to creator)")
	destroyAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Creator account address for asset to destroy")
	destroyAssetCmd.Flags().Uint64Var((*uint64)(&assetID), "assetid", 0, "Asset ID to destroy")
	destroyAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of asset to destroy")

	configAssetCmd.Flags().StringVar(&assetManager, "manager", "", "Manager account to issue the config transaction")
	configAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset to configure (defaults to manager)")
	configAssetCmd.Flags().Uint64Var((*uint64)(&assetID), "assetid", 0, "Asset ID to configure")
	configAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of asset to configure")
	configAssetCmd.Flags().StringVar(&assetNewManager, "new-manager", "", "New manager address")
	configAssetCmd.Flags().StringVar(&assetNewReserve, "new-reserve", "", "New reserve address")
	configAssetCmd.Flags().StringVar(&assetNewFreezer, "new-freezer", "", "New freeze address")
	configAssetCmd.Flags().StringVar(&assetNewClawback, "new-clawback", "", "New clawback address")
	configAssetCmd.MarkFlagRequired("manager")

	sendAssetCmd.Flags().StringVar(&assetClawback, "clawback", "", "Address to issue a clawback transaction from (defaults to no clawback)")
	sendAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset creator")
	sendAssetCmd.Flags().Uint64Var((*uint64)(&assetID), "assetid", 0, "ID of the asset being transferred")
	sendAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of the asset being transferred")
	sendAssetCmd.Flags().StringVarP(&account, "from", "f", "", "Account address to send the money from (if not specified, uses default account)")
	sendAssetCmd.Flags().StringVarP(&toAddress, "to", "t", "", "Address to send to money to (required)")
	sendAssetCmd.Flags().Uint64VarP(&amount, "amount", "a", 0, "The amount to be transferred (required), in base units of the asset.")
	sendAssetCmd.Flags().StringVarP(&closeToAddress, "close-to", "c", "", "Close asset account and send remainder to this address")
	sendAssetCmd.MarkFlagRequired("to")
	sendAssetCmd.MarkFlagRequired("amount")

	freezeAssetCmd.Flags().StringVar(&assetFreezer, "freezer", "", "Address to issue a freeze transaction from")
	freezeAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset creator")
	freezeAssetCmd.Flags().Uint64Var((*uint64)(&assetID), "assetid", 0, "ID of the asset being frozen")
	freezeAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of the asset being frozen")
	freezeAssetCmd.Flags().StringVar(&account, "account", "", "Account address to freeze/unfreeze")
	freezeAssetCmd.Flags().BoolVar(&assetFrozen, "freeze", false, "Freeze or unfreeze")
	freezeAssetCmd.MarkFlagRequired("freezer")
	freezeAssetCmd.MarkFlagRequired("account")
	freezeAssetCmd.MarkFlagRequired("freeze")

	optinAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of the asset being accepted")
	optinAssetCmd.Flags().Uint64Var((*uint64)(&assetID), "assetid", 0, "ID of the asset being accepted")
	optinAssetCmd.Flags().StringVarP(&account, "account", "a", "", "Account address to opt in to using the asset (if not specified, uses default account)")
	optinAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset creator")

	// Add common transaction flags to all txn-generating asset commands
	addTxnFlags(createAssetCmd)
	addTxnFlags(destroyAssetCmd)
	addTxnFlags(configAssetCmd)
	addTxnFlags(sendAssetCmd)
	addTxnFlags(freezeAssetCmd)
	addTxnFlags(optinAssetCmd)

	infoAssetCmd.Flags().Uint64Var((*uint64)(&assetID), "assetid", 0, "ID of the asset to look up")
	infoAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "DEPRECATED! Unit name of the asset to look up")
	infoAssetCmd.Flags().StringVar(&assetUnitName, "unitname", "", "Unit name of the asset to look up")
	infoAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address of the asset creator")
}

var assetCmd = &cobra.Command{
	Use:   "asset",
	Short: "Manage assets",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

func lookupAssetID(cmd *cobra.Command, creator string, client libgoal.Client) {
	if cmd.Flags().Changed("asset") {
		reportWarnln("The [--asset] flag is deprecated and will be removed in a future release, use [--unitname] instead.")
	}

	if cmd.Flags().Changed("asset") && cmd.Flags().Changed("unitname") {
		reportErrorf("The [--asset] flag has been replaced by [--unitname], do not provide both flags.")
	}

	assetOrUnit := cmd.Flags().Changed("asset") || cmd.Flags().Changed("unitname")

	if cmd.Flags().Changed("assetid") && assetOrUnit {
		reportErrorf("Only one of [--assetid] or [--unitname and --creator] should be specified")
	}

	if cmd.Flags().Changed("assetid") {
		return
	}

	if !assetOrUnit {
		reportErrorf("Missing required parameter [--assetid] or [--unitname and --creator] must be specified")
	}

	if !cmd.Flags().Changed("creator") {
		reportErrorf("Asset creator must be specified if finding asset by name. " +
			"Use the asset's integer identifier [--assetid] if the " +
			"creator account is unknown.")
	}

	response, err := client.AccountInformation(creator, true)
	if err != nil {
		reportErrorf(errorRequestFail, err)
	}

	nmatch := 0
	if response.CreatedAssets != nil {
		for _, asset := range *response.CreatedAssets {
			params := asset.Params
			if params.UnitName == nil && assetUnitName == "" {
				// Since asset unit names can be left blank, try to match
				// empty unit names in the user's account first.
				assetID = asset.Index
				nmatch++
			} else if params.UnitName != nil && *params.UnitName == assetUnitName {
				assetID = asset.Index
				nmatch++
			}
		}
	}

	if nmatch == 0 {
		reportErrorf("No matches for asset unit name %s in creator %s; assets %v", assetUnitName, creator, *response.CreatedAssets)
	}

	if nmatch > 1 {
		reportErrorf("Multiple matches for asset unit name %s in creator %s", assetUnitName, creator)
	}
}

var createAssetCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an asset",
	Long:  "Post a transaction declaring and issuing a new layer-one asset on the network.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		checkTxValidityPeriodCmdFlags(cmd)

		if assetManager != "" && assetNoManager {
			reportErrorf("The [--manager] flag and the [--no-manager] flag are mutually exclusive, do not provide both flags.")
		}

		if assetReserve != "" && assetNoReserve {
			reportErrorf("The [--reserve] flag and the [--no-reserve] flag are mutually exclusive, do not provide both flags.")
		}

		if assetFreezer != "" && assetNoFreezer {
			reportErrorf("The [--freezer] flag and the [--no-freezer] flag are mutually exclusive, do not provide both flags.")
		}

		if assetClawback != "" && assetNoClawback {
			reportErrorf("The [--clawback] flag and the [--no-clawback] flag are mutually exclusive, do not provide both flags.")
		}

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		creator := accountList.getAddressByName(assetCreator)
		manager := creator
		reserve := creator
		freezer := creator
		clawback := creator

		if cmd.Flags().Changed("manager") {
			assetManager = accountList.getAddressByName(assetManager)
			manager = assetManager
		}

		if assetNoManager {
			manager = ""
		}

		if cmd.Flags().Changed("reserve") {
			assetReserve = accountList.getAddressByName(assetReserve)
			reserve = assetReserve
		}

		if assetNoReserve {
			reserve = ""
		}

		if cmd.Flags().Changed("freezer") {
			assetFreezer = accountList.getAddressByName(assetFreezer)
			freezer = assetFreezer
		}

		if assetNoFreezer {
			freezer = ""
		}

		if cmd.Flags().Changed("clawback") {
			assetClawback = accountList.getAddressByName(assetClawback)
			clawback = assetClawback
		}

		if assetNoClawback {
			clawback = ""
		}

		var err error
		var assetMetadataHash []byte
		if assetMetadataHashBase64 != "" {
			assetMetadataHash, err = base64.StdEncoding.DecodeString(assetMetadataHashBase64)
			if err != nil {
				reportErrorf(malformedMetadataHash, assetMetadataHashBase64, err)
			}
		}

		tx, err := client.MakeUnsignedAssetCreateTx(assetTotal, assetFrozen, manager, reserve, freezer, clawback, assetUnitName, assetName, assetURL, assetMetadataHash, assetDecimals)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(creator, fv, lv, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err2 := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, tx)
			if err2 != nil {
				reportErrorf(errorSigningTX, err2)
			}

			txid, err2 := client.BroadcastTransaction(signedTxn)
			if err2 != nil {
				reportErrorf(errorBroadcastingTX, err2)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				txn, err1 := waitForCommit(client, txid, lv)
				if err1 != nil {
					reportErrorln(err1)
				}
				if txn.AssetIndex != nil && *txn.AssetIndex != 0 {
					reportInfof("Created asset with asset index %d", *txn.AssetIndex)
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorln(err)
			}
		}
	},
}

var destroyAssetCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy an asset",
	Long:  `Issue a transaction deleting an asset from the network. This transaction must be issued by the asset manager while the creator holds all of the asset's tokens.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

		if assetManager == "" && assetCreator == "" {
			reportErrorf("Missing required parameter [--manager] or [--creator]")
		}

		if assetManager == "" {
			assetManager = assetCreator
		}

		creator := accountList.getAddressByName(assetCreator)
		manager := accountList.getAddressByName(assetManager)

		lookupAssetID(cmd, creator, client)

		tx, err := client.MakeUnsignedAssetDestroyTx(assetID)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(manager, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err2 := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, tx)
			if err2 != nil {
				reportErrorf(errorSigningTX, err2)
			}

			txid, err2 := client.BroadcastTransaction(signedTxn)
			if err2 != nil {
				reportErrorf(errorBroadcastingTX, err2)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				_, err2 = waitForCommit(client, txid, lastValid)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorln(err)
			}
		}
	},
}

var configAssetCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure an asset",
	Long:  `Change an asset configuration. This transaction must be issued by the asset manager. This allows any management address to be changed: manager, freezer, reserve, or clawback.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

		if assetCreator == "" {
			assetCreator = assetManager
		}

		creator := accountList.getAddressByName(assetCreator)
		manager := accountList.getAddressByName(assetManager)

		lookupAssetID(cmd, creator, client)

		var newManager, newReserve, newFreeze, newClawback *string
		if cmd.Flags().Changed("new-manager") {
			assetNewManager = accountList.getAddressByName(assetNewManager)
			newManager = &assetNewManager
		}

		if cmd.Flags().Changed("new-reserve") {
			assetNewReserve = accountList.getAddressByName(assetNewReserve)
			newReserve = &assetNewReserve
		}

		if cmd.Flags().Changed("new-freezer") {
			assetNewFreezer = accountList.getAddressByName(assetNewFreezer)
			newFreeze = &assetNewFreezer
		}

		if cmd.Flags().Changed("new-clawback") {
			assetNewClawback = accountList.getAddressByName(assetNewClawback)
			newClawback = &assetNewClawback
		}

		tx, err := client.MakeUnsignedAssetConfigTx(creator, assetID, newManager, newReserve, newFreeze, newClawback)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(manager, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err2 := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, tx)
			if err2 != nil {
				reportErrorf(errorSigningTX, err2)
			}

			txid, err2 := client.BroadcastTransaction(signedTxn)
			if err2 != nil {
				reportErrorf(errorBroadcastingTX, err2)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				_, err2 = waitForCommit(client, txid, lastValid)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorln(err)
			}
		}
	},
}

var sendAssetCmd = &cobra.Command{
	Use:   "send",
	Short: "Transfer assets",
	Long:  "Transfer asset holdings. An account can begin accepting an asset by issuing a zero-amount asset transfer to itself.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

		// Check if from was specified, else use default
		if account == "" {
			account = accountList.getDefaultAccount()
		}

		sender := accountList.getAddressByName(account)
		toAddressResolved := accountList.getAddressByName(toAddress)
		creatorResolved := accountList.getAddressByName(assetCreator)

		lookupAssetID(cmd, creatorResolved, client)

		var senderForClawback string
		if assetClawback != "" {
			senderForClawback = sender
			sender = accountList.getAddressByName(assetClawback)
		}

		var closeToAddressResolved string
		if closeToAddress != "" {
			closeToAddressResolved = accountList.getAddressByName(closeToAddress)
		}

		tx, err := client.MakeUnsignedAssetSendTx(assetID, amount, toAddressResolved, closeToAddressResolved, senderForClawback)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}

		tx, err = client.FillUnsignedTxTemplate(sender, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err2 := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, tx)
			if err2 != nil {
				reportErrorf(errorSigningTX, err2)
			}

			txid, err2 := client.BroadcastTransaction(signedTxn)
			if err2 != nil {
				reportErrorf(errorBroadcastingTX, err2)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				_, err2 = waitForCommit(client, txid, lastValid)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorln(err)
			}
		}
	},
}

var freezeAssetCmd = &cobra.Command{
	Use:   "freeze",
	Short: "Freeze assets",
	Long:  `Freeze or unfreeze assets for a target account. The transaction must be issued by the freeze address for the asset in question.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

		freezer := accountList.getAddressByName(assetFreezer)
		creatorResolved := accountList.getAddressByName(assetCreator)
		accountResolved := accountList.getAddressByName(account)

		lookupAssetID(cmd, creatorResolved, client)

		tx, err := client.MakeUnsignedAssetFreezeTx(assetID, accountResolved, assetFrozen)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(freezer, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err2 := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, tx)
			if err2 != nil {
				reportErrorf(errorSigningTX, err2)
			}

			txid, err2 := client.BroadcastTransaction(signedTxn)
			if err2 != nil {
				reportErrorf(errorBroadcastingTX, err2)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				_, err2 = waitForCommit(client, txid, lastValid)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorln(err)
			}
		}
	},
}

func assetDecimalsFmt(amount uint64, decimals uint64) string {
	// Just return the raw amount with no decimal if decimals is 0
	if decimals == 0 {
		return fmt.Sprintf("%d", amount)
	}

	// Otherwise, ensure there are decimals digits to the right of the decimal point
	pow := uint64(1)
	for i := uint64(0); i < decimals; i++ {
		pow *= 10
	}
	return fmt.Sprintf("%d.%0*d", amount/pow, decimals, amount%pow)
}

var optinAssetCmd = &cobra.Command{
	Use:   "optin",
	Short: "Optin to assets",
	Long:  "Opt in to receive a new asset. An account will begin accepting an asset by issuing a zero-amount asset transfer to itself.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		// Opt in txns are always 0
		const xferAmount uint64 = 0

		creatorResolved := accountList.getAddressByName(assetCreator)

		lookupAssetID(cmd, creatorResolved, client)

		// Check if from was specified, else use default
		if account == "" {
			account = accountList.getDefaultAccount()
		}
		tx, err := client.MakeUnsignedAssetSendTx(assetID, xferAmount, account, "", "")
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}

		tx, err = client.FillUnsignedTxTemplate(account, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err2 := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, tx)
			if err2 != nil {
				reportErrorf(errorSigningTX, err2)
			}

			txid, err2 := client.BroadcastTransaction(signedTxn)
			if err2 != nil {
				reportErrorf(errorBroadcastingTX, err2)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				_, err2 = waitForCommit(client, txid, lastValid)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorln(err)
			}
		}
	},
}

var infoAssetCmd = &cobra.Command{
	Use:   "info",
	Short: "Look up current parameters for an asset",
	Long:  `Look up asset information stored on the network, such as asset creator, management addresses, or asset name.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		creator := accountList.getAddressByName(assetCreator)

		// Helper methods for dereferencing optional asset fields.
		derefString := func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		}
		derefBool := func(b *bool) bool {
			if b == nil {
				return false
			}
			return *b
		}

		lookupAssetID(cmd, creator, client)

		asset, err := client.AssetInformation(assetID)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		reserveEmpty := false
		if derefString(asset.Params.Reserve) == "" {
			reserveEmpty = true
			asset.Params.Reserve = &asset.Params.Creator
		}

		reserve, err := client.AccountAssetInformation(*asset.Params.Reserve, assetID)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		res := reserve.AssetHolding

		fmt.Printf("Asset ID:         %d\n", assetID)
		fmt.Printf("Creator:          %s\n", asset.Params.Creator)
		reportInfof("Asset name:       %s", derefString(asset.Params.Name))
		reportInfof("Unit name:        %s", derefString(asset.Params.UnitName))
		reportInfof("URL:              %s", derefString(asset.Params.Url))
		fmt.Printf("Maximum issue:    %s %s\n", assetDecimalsFmt(asset.Params.Total, asset.Params.Decimals), derefString(asset.Params.UnitName))
		fmt.Printf("Reserve amount:   %s %s\n", assetDecimalsFmt(res.Amount, asset.Params.Decimals), derefString(asset.Params.UnitName))
		fmt.Printf("Issued:           %s %s\n", assetDecimalsFmt(asset.Params.Total-res.Amount, asset.Params.Decimals), derefString(asset.Params.UnitName))
		fmt.Printf("Decimals:         %d\n", asset.Params.Decimals)
		fmt.Printf("Default frozen:   %v\n", derefBool(asset.Params.DefaultFrozen))
		fmt.Printf("Manager address:  %s\n", derefString(asset.Params.Manager))
		if reserveEmpty {
			fmt.Printf("Reserve address:  %s (Empty. Defaulting to creator)\n", derefString(asset.Params.Reserve))
		} else {
			fmt.Printf("Reserve address:  %s\n", derefString(asset.Params.Reserve))
		}
		fmt.Printf("Freeze address:   %s\n", derefString(asset.Params.Freeze))
		fmt.Printf("Clawback address: %s\n", derefString(asset.Params.Clawback))
	},
}
