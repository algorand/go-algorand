// Copyright (C) 2019 Algorand, Inc.
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
	numValidRounds          uint64
	assetID                 uint64
	assetCreator            string
	assetTotal              uint64
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

	createAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for creating an asset")
	createAssetCmd.Flags().Uint64Var(&assetTotal, "total", 0, "Total amount of tokens for created asset")
	createAssetCmd.Flags().BoolVar(&assetFrozen, "defaultfrozen", false, "Freeze or not freeze holdings by default")
	createAssetCmd.Flags().StringVar(&assetUnitName, "unitname", "", "Name for the unit of asset")
	createAssetCmd.Flags().StringVar(&assetName, "name", "", "Name for the entire asset")
	createAssetCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	createAssetCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	createAssetCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	createAssetCmd.Flags().StringVar(&assetURL, "asseturl", "", "URL where user can access more information about the asset (max 32 bytes)")
	createAssetCmd.Flags().StringVar(&assetMetadataHashBase64, "assetmetadatab64", "", "base-64 encoded 32-byte commitment to asset metadata")
	createAssetCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	createAssetCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	createAssetCmd.Flags().StringVar(&noteBase64, "noteb64", "", "Note (URL-base64 encoded)")
	createAssetCmd.Flags().StringVarP(&noteText, "note", "n", "", "Note text (ignored if --noteb64 used also)")
	createAssetCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	createAssetCmd.MarkFlagRequired("total")
	createAssetCmd.MarkFlagRequired("creator")

	destroyAssetCmd.Flags().StringVar(&assetManager, "manager", "", "Manager account to issue the destroy transaction (defaults to creator)")
	destroyAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset to destroy")
	destroyAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "Asset ID to destroy")
	destroyAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of asset to destroy")
	destroyAssetCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	destroyAssetCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	destroyAssetCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	destroyAssetCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	destroyAssetCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	destroyAssetCmd.Flags().StringVar(&noteBase64, "noteb64", "", "Note (URL-base64 encoded)")
	destroyAssetCmd.Flags().StringVarP(&noteText, "note", "n", "", "Note text (ignored if --noteb64 used also)")
	destroyAssetCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")

	configAssetCmd.Flags().StringVar(&assetManager, "manager", "", "Manager account to issue the config transaction (defaults to creator)")
	configAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset to configure")
	configAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "Asset ID to configure")
	configAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of asset to configure")
	configAssetCmd.Flags().StringVar(&assetNewManager, "new-manager", "", "New manager address")
	configAssetCmd.Flags().StringVar(&assetNewReserve, "new-reserve", "", "New reserve address")
	configAssetCmd.Flags().StringVar(&assetNewFreezer, "new-freezer", "", "New freeze address")
	configAssetCmd.Flags().StringVar(&assetNewClawback, "new-clawback", "", "New clawback address")
	configAssetCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	configAssetCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	configAssetCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	configAssetCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	configAssetCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	configAssetCmd.Flags().StringVar(&noteBase64, "noteb64", "", "Note (URL-base64 encoded)")
	configAssetCmd.Flags().StringVarP(&noteText, "note", "n", "", "Note text (ignored if --noteb64 used also)")
	configAssetCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	configAssetCmd.MarkFlagRequired("manager")

	sendAssetCmd.Flags().StringVar(&assetClawback, "clawback", "", "Address to issue a clawback transaction from (defaults to no clawback)")
	sendAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset creator")
	sendAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "ID of the asset being transferred")
	sendAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of the asset being transferred")
	sendAssetCmd.Flags().StringVarP(&account, "from", "f", "", "Account address to send the money from (if not specified, uses default account)")
	sendAssetCmd.Flags().StringVarP(&toAddress, "to", "t", "", "Address to send to money to (required)")
	sendAssetCmd.Flags().Uint64VarP(&amount, "amount", "a", 0, "The amount to be transferred (required), in microAlgos")
	sendAssetCmd.Flags().StringVarP(&closeToAddress, "close-to", "c", "", "Close asset account and send remainder to this address")
	sendAssetCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	sendAssetCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	sendAssetCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	sendAssetCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	sendAssetCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	sendAssetCmd.Flags().StringVar(&noteBase64, "noteb64", "", "Note (URL-base64 encoded)")
	sendAssetCmd.Flags().StringVarP(&noteText, "note", "n", "", "Note text (ignored if --noteb64 used also)")
	sendAssetCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	sendAssetCmd.MarkFlagRequired("to")
	sendAssetCmd.MarkFlagRequired("amount")

	freezeAssetCmd.Flags().StringVar(&assetFreezer, "freezer", "", "Address to issue a freeze transaction from")
	freezeAssetCmd.Flags().StringVar(&assetCreator, "creator", "", "Account address for asset creator")
	freezeAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "ID of the asset being frozen")
	freezeAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of the asset being frozen")
	freezeAssetCmd.Flags().StringVar(&account, "account", "", "Account address to freeze/unfreeze")
	freezeAssetCmd.Flags().BoolVar(&assetFrozen, "freeze", false, "Freeze or unfreeze")
	freezeAssetCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	freezeAssetCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	freezeAssetCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	freezeAssetCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	freezeAssetCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	freezeAssetCmd.Flags().StringVar(&noteBase64, "noteb64", "", "Note (URL-base64 encoded)")
	freezeAssetCmd.Flags().StringVarP(&noteText, "note", "n", "", "Note text (ignored if --noteb64 used also)")
	freezeAssetCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	freezeAssetCmd.MarkFlagRequired("freezer")
	freezeAssetCmd.MarkFlagRequired("account")
	freezeAssetCmd.MarkFlagRequired("freeze")

	infoAssetCmd.Flags().Uint64Var(&assetID, "assetid", 0, "ID of the asset to look up")
	infoAssetCmd.Flags().StringVar(&assetUnitName, "asset", "", "Unit name of the asset to look up")
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
	if cmd.Flags().Changed("assetid") && cmd.Flags().Changed("asset") {
		reportErrorf("Only one of [-assetid] or [-asset and -creator] can be specified")
	}

	if cmd.Flags().Changed("assetid") {
		return
	}

	if !cmd.Flags().Changed("asset") {
		reportErrorf("Either [-assetid] or [-asset and -creator]  must be specified")
	}

	if !cmd.Flags().Changed("creator") {
		reportErrorf("Asset creator must be specified if finding asset by name. " +
			"Use the asset's integer identifier (-assetid) if the " +
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
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
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

		tx, err := client.MakeUnsignedAssetCreateTx(assetTotal, assetFrozen, creator, creator, creator, creator, assetUnitName, assetName, assetURL, assetMetadataHash)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		tx.Note = parseNoteField(cmd)

		tx, err = client.FillUnsignedTxTemplate(creator, firstValid, numValidRounds, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if txFilename == "" {
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
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var destroyAssetCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy an asset",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
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

		tx, err = client.FillUnsignedTxTemplate(manager, firstValid, numValidRounds, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if txFilename == "" {
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
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var configAssetCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure an asset",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
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

		tx, err = client.FillUnsignedTxTemplate(manager, firstValid, numValidRounds, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if txFilename == "" {
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
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var sendAssetCmd = &cobra.Command{
	Use:   "send",
	Short: "Transfer assets",
	Long:  "Transfer asset holdings.  Use a zero self-transfer to add an asset to an account in the first place.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
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

		tx, err = client.FillUnsignedTxTemplate(sender, firstValid, numValidRounds, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if txFilename == "" {
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
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var freezeAssetCmd = &cobra.Command{
	Use:   "freeze",
	Short: "Freeze assets",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
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

		tx, err = client.FillUnsignedTxTemplate(freezer, firstValid, numValidRounds, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		if txFilename == "" {
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
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var infoAssetCmd = &cobra.Command{
	Use:   "info",
	Short: "Look up current parameters for an asset",
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

		if params.ReserveAddr == "" {
			params.ReserveAddr = params.Creator
		}

		reserve, err := client.AccountInformation(params.ReserveAddr)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		fmt.Printf("Asset ID:         %d\n", assetID)
		fmt.Printf("Creator:          %s\n", params.Creator)
		fmt.Printf("Asset name:       %s\n", params.AssetName)
		fmt.Printf("Unit name:        %s\n", params.UnitName)
		fmt.Printf("Maximum issue:    %d %s\n", params.Total, params.UnitName)
		fmt.Printf("Reserve amount:   %d %s\n", reserve.Assets[assetID].Amount, params.UnitName)
		fmt.Printf("Issued:           %d %s\n", params.Total-reserve.Assets[assetID].Amount, params.UnitName)
		fmt.Printf("Default frozen:   %v\n", params.DefaultFrozen)
		fmt.Printf("Manager address:  %s\n", params.ManagerAddr)
		fmt.Printf("Reserve address:  %s\n", params.ReserveAddr)
		fmt.Printf("Freeze address:   %s\n", params.FreezeAddr)
		fmt.Printf("Clawback address: %s\n", params.ClawbackAddr)
	},
}
