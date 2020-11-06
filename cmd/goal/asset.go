// Copyright (C) 2019-2020 Algorand, Inc.
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

	"github.com/algorand/go-algorand/libgoal"
)

var (
	assetID                 uint64
	assetCreator            string
	assetTotal              uint64
	assetDecimals           uint32
	assetFrozen             bool
	assetUnitName           string
	assetMetadataHashBase64 string
	assetURL                string
	assetName               string
	assetManager            string
	assetClawback           string
	assetFreezer            string

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

	assetCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")

	createAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for creating an asset")
	createAssetCmd.Flags().Uint64Var(&assetTotal, "total", 0, "Total amount of tokens for created asset")
	createAssetCmd.Flags().Uint32Var(&assetDecimals, "decimals", 0, "The number of digits to use after the decimal point when displaying this asset. If set to 0, the asset is not divisible beyond its base unit. If set to 1, the base asset unit is tenths. If 2, the base asset unit is hundredths, and so on.")
	createAssetCmd.Flags().BoolVar(&assetFrozen, "defaultfrozen", false, "Freeze or not freeze holdings by default")
	createAssetCmd.Flags().StringVar(&assetUnitName, "unitname", "", "Name for the unit of asset")
	createAssetCmd.Flags().StringVar(&assetName, "name", "", "Name for the entire asset")
	createAssetCmd.Flags().StringVar(&assetURL, "asseturl", "", "URL where user can access more information about the asset (max 32 bytes)")
	createAssetCmd.Flags().StringVar(&assetMetadataHashBase64, "assetmetadatab64", "", "base-64 encoded 32-byte commitment to asset metadata")
	createAssetCmd.MarkFlagRequired("total")
	createAssetCmd.MarkFlagRequired("creator")

	destroyAssetCmd.Flags().StringVar(&assetManager, "manager", "", "Manager account to issue the destroy transaction (defaults to creator)")
	destroyAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Creator account address for asset to destroy")
	destroyAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "Asset ID to destroy")
	destroyAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of asset to destroy")

	configAssetCmd.Flags().StringVar(&assetManager, "manager", "", "Manager account to issue the config transaction (defaults to creator)")
	configAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset to configure")
	configAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "Asset ID to configure")
	configAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of asset to configure")
	configAssetCmd.Flags().StringVar(&assetNewManager, "new-manager", "", "New manager address")
	configAssetCmd.Flags().StringVar(&assetNewReserve, "new-reserve", "", "New reserve address")
	configAssetCmd.Flags().StringVar(&assetNewFreezer, "new-freezer", "", "New freeze address")
	configAssetCmd.Flags().StringVar(&assetNewClawback, "new-clawback", "", "New clawback address")
	configAssetCmd.MarkFlagRequired("manager")

	sendAssetCmd.Flags().StringVar(&assetClawback, "clawback", "", "Address to issue a clawback transaction from (defaults to no clawback)")
	sendAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset creator")
	sendAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "ID of the asset being transferred")
	sendAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of the asset being transferred")
	sendAssetCmd.Flags().StringVarP(&account, "from", "f", "", "Account address to send the money from (if not specified, uses default account)")
	sendAssetCmd.Flags().StringVarP(&toAddress, "to", "t", "", "Address to send to money to (required)")
	sendAssetCmd.Flags().Uint64VarP(&amount, "amount", "a", 0, "The amount to be transferred (required), in base units of the asset.")
	sendAssetCmd.Flags().StringVarP(&closeToAddress, "close-to", "c", "", "Close asset account and send remainder to this address")
	sendAssetCmd.MarkFlagRequired("to")
	sendAssetCmd.MarkFlagRequired("amount")

	freezeAssetCmd.Flags().StringVar(&assetFreezer, "freezer", "", "Address to issue a freeze transaction from")
	freezeAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset creator")
	freezeAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "ID of the asset being frozen")
	freezeAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of the asset being frozen")
	freezeAssetCmd.Flags().StringVar(&account, "account", "", "Account address to freeze/unfreeze")
	freezeAssetCmd.Flags().BoolVar(&assetFrozen, "freeze", false, "Freeze or unfreeze")
	freezeAssetCmd.MarkFlagRequired("freezer")
	freezeAssetCmd.MarkFlagRequired("account")
	freezeAssetCmd.MarkFlagRequired("freeze")

	// Add common transaction flags to all txn-generating asset commands
	addTxnFlags(createAssetCmd)
	addTxnFlags(destroyAssetCmd)
	addTxnFlags(configAssetCmd)
	addTxnFlags(sendAssetCmd)
	addTxnFlags(freezeAssetCmd)

	infoAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "ID of the asset to look up")
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
		reportErrorf("Either [--assetid] or [--unitname and --creator] must be specified")
	}

	if !cmd.Flags().Changed("creator") {
		reportErrorf("Asset creator must be specified if finding asset by name. " +
			"Use the asset's integer identifier [--assetid] if the " +
			"creator account is unknown.")
	}

	response, err := client.AccountInformation(creator)
	if err != nil {
		reportErrorf(errorRequestFail, err)
	}

	nmatch := 0
	for id, params := range response.AssetParams {
		if params.UnitName == assetUnitName {
			assetID = id
			nmatch++
		}
	}

	if nmatch == 0 {
		reportErrorf("No matches for asset unit name %s in creator %s", assetUnitName, creator)
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

		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		creator := accountList.getAddressByName(assetCreator)

		var err error
		var assetMetadataHash []byte
		if assetMetadataHashBase64 != "" {
			assetMetadataHash, err = base64.StdEncoding.DecodeString(assetMetadataHashBase64)
			if err != nil {
				reportErrorf(malformedMetadataHash, assetMetadataHashBase64, err)
			}
		}

		tx, err := client.MakeUnsignedAssetCreateTx(assetTotal, assetFrozen, creator, creator, creator, creator, assetUnitName, assetName, assetURL, assetMetadataHash, assetDecimals)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		fv, lv, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(creator, fv, lv, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err := client.SignTransactionWithWallet(wh, pw, tx)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			txid, err := client.BroadcastTransaction(signedTxn)
			if err != nil {
				reportErrorf(errorBroadcastingTX, err)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid)
				if err != nil {
					reportErrorf(err.Error())
				}
				// Check if we know about the transaction yet
				txn, err := client.PendingTransactionInformation(txid)
				if err != nil {
					reportErrorf(err.Error())
				}
				if txn.TransactionResults != nil && txn.TransactionResults.CreatedAssetIndex != 0 {
					reportInfof("Created asset with asset index %d", txn.TransactionResults.CreatedAssetIndex)
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var destroyAssetCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy an asset",
	Long:  `Issue a transaction deleting an asset from the network. This transaction must be issued by the asset manager while the creator holds all asset tokens.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

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

		firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(manager, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err := client.SignTransactionWithWallet(wh, pw, tx)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			txid, err := client.BroadcastTransaction(signedTxn)
			if err != nil {
				reportErrorf(errorBroadcastingTX, err)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorf(err.Error())
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

		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

		if assetManager == "" {
			assetManager = assetCreator
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

		firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(manager, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err := client.SignTransactionWithWallet(wh, pw, tx)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			txid, err := client.BroadcastTransaction(signedTxn)
			if err != nil {
				reportErrorf(errorBroadcastingTX, err)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorf(err.Error())
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

		dataDir := ensureSingleDataDir()
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

		firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(sender, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err := client.SignTransactionWithWallet(wh, pw, tx)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			txid, err := client.BroadcastTransaction(signedTxn)
			if err != nil {
				reportErrorf(errorBroadcastingTX, err)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorf(err.Error())
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

		dataDir := ensureSingleDataDir()
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

		firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}
		tx, err = client.FillUnsignedTxTemplate(freezer, firstValid, lastValid, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if outFilename == "" {
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err := client.SignTransactionWithWallet(wh, pw, tx)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			txid, err := client.BroadcastTransaction(signedTxn)
			if err != nil {
				reportErrorf(errorBroadcastingTX, err)
			}

			// Report tx details to user
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

func assetDecimalsFmt(amount uint64, decimals uint32) string {
	// Just return the raw amount with no decimal if decimals is 0
	if decimals == 0 {
		return fmt.Sprintf("%d", amount)
	}

	// Otherwise, ensure there are decimals digits to the right of the decimal point
	pow := uint64(1)
	for i := uint32(0); i < decimals; i++ {
		pow *= 10
	}
	return fmt.Sprintf("%d.%0*d", amount/pow, decimals, amount%pow)
}

var infoAssetCmd = &cobra.Command{
	Use:   "info",
	Short: "Look up current parameters for an asset",
	Long:  `Look up asset information stored on the network, such as asset creator, management addresses, or asset name.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		creator := accountList.getAddressByName(assetCreator)

		lookupAssetID(cmd, creator, client)

		params, err := client.AssetInformation(assetID)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		reserveEmpty := false
		if params.ReserveAddr == "" {
			reserveEmpty = true
			params.ReserveAddr = params.Creator
		}

		reserve, err := client.AccountInformation(params.ReserveAddr)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		res := reserve.Assets[assetID]

		fmt.Printf("Asset ID:         %d\n", assetID)
		fmt.Printf("Creator:          %s\n", params.Creator)
		reportInfof("Asset name:       %s\n", params.AssetName)
		reportInfof("Unit name:        %s\n", params.UnitName)
		fmt.Printf("Maximum issue:    %s %s\n", assetDecimalsFmt(params.Total, params.Decimals), params.UnitName)
		fmt.Printf("Reserve amount:   %s %s\n", assetDecimalsFmt(res.Amount, params.Decimals), params.UnitName)
		fmt.Printf("Issued:           %s %s\n", assetDecimalsFmt(params.Total-res.Amount, params.Decimals), params.UnitName)
		fmt.Printf("Decimals:         %d\n", params.Decimals)
		fmt.Printf("Default frozen:   %v\n", params.DefaultFrozen)
		fmt.Printf("Manager address:  %s\n", params.ManagerAddr)
		if reserveEmpty {
			fmt.Printf("Reserve address:  %s (Empty. Defaulting to creator)\n", params.ReserveAddr)
		} else {
			fmt.Printf("Reserve address:  %s\n", params.ReserveAddr)
		}
		fmt.Printf("Freeze address:   %s\n", params.FreezeAddr)
		fmt.Printf("Clawback address: %s\n", params.ClawbackAddr)
	},
}
