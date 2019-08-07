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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"

	"github.com/spf13/cobra"
)

var (
	numValidRounds   uint64
	currencyID       uint64
	currencyCreator  string
	currencyTotal    uint64
	currencyFrozen   bool
	currencyUnitName string
	currencyManager  string

	currencyNewManager  string
	currencyNewReserve  string
	currencyNewFreezer  string
	currencyNewClawback string
)

func init() {
	currencyCmd.AddCommand(createCurrencyCmd)
	currencyCmd.AddCommand(destroyCurrencyCmd)
	currencyCmd.AddCommand(configCurrencyCmd)
	currencyCmd.AddCommand(sendCurrencyCmd)
	currencyCmd.AddCommand(infoCurrencyCmd)

	createCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for creating a sub-currency")
	createCurrencyCmd.Flags().Uint64Var(&currencyTotal, "total", 0, "Total amount of tokens for created sub-currency")
	createCurrencyCmd.Flags().BoolVar(&currencyFrozen, "defaultfrozen", false, "Freeze or not freeze holdings by default")
	createCurrencyCmd.Flags().StringVar(&currencyUnitName, "unitname", "", "Name for the unit of currency")
	createCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	createCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	createCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	createCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	createCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	createCurrencyCmd.MarkFlagRequired("creator")
	createCurrencyCmd.MarkFlagRequired("total")

	destroyCurrencyCmd.Flags().StringVar(&currencyManager, "manager", "", "Manager account to issue the destroy transaction (defaults to creator)")
	destroyCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for sub-currency to destroy")
	destroyCurrencyCmd.Flags().Uint64Var(&currencyID, "currency", 0, "Currency ID to destroy")
	destroyCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	destroyCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	destroyCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	destroyCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	destroyCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	destroyCurrencyCmd.MarkFlagRequired("creator")
	destroyCurrencyCmd.MarkFlagRequired("currency")

	configCurrencyCmd.Flags().StringVar(&currencyManager, "manager", "", "Manager account to issue the config transaction (defaults to creator)")
	configCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for sub-currency to configure")
	configCurrencyCmd.Flags().Uint64Var(&currencyID, "currency", 0, "Currency ID to configure")
	configCurrencyCmd.Flags().StringVar(&currencyNewManager, "new-manager", "", "New manager address")
	configCurrencyCmd.Flags().StringVar(&currencyNewReserve, "new-reserve", "", "New reserve address")
	configCurrencyCmd.Flags().StringVar(&currencyNewFreezer, "new-freeze", "", "New freeze address")
	configCurrencyCmd.Flags().StringVar(&currencyNewClawback, "new-clawback", "", "New clawback address")
	configCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	configCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	configCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	configCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	configCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	configCurrencyCmd.MarkFlagRequired("creator")
	configCurrencyCmd.MarkFlagRequired("currency")

	sendCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for sub-currency creator")
	sendCurrencyCmd.Flags().Uint64Var(&currencyID, "currency", 0, "ID of the sub-currency being transferred")
	sendCurrencyCmd.Flags().StringVarP(&account, "from", "f", "", "Account address to send the money from (if not specified, uses default account)")
	sendCurrencyCmd.Flags().StringVarP(&toAddress, "to", "t", "", "Address to send to money to (required)")
	sendCurrencyCmd.Flags().Uint64VarP(&amount, "amount", "a", 0, "The amount to be transferred (required), in microAlgos")
	sendCurrencyCmd.Flags().StringVarP(&closeToAddress, "close-to", "c", "", "Close sub-currency account and send remainder to this address")
	sendCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	sendCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	sendCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	sendCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	sendCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	sendCurrencyCmd.MarkFlagRequired("creator")
	sendCurrencyCmd.MarkFlagRequired("currency")
	sendCurrencyCmd.MarkFlagRequired("to")
	sendCurrencyCmd.MarkFlagRequired("amount")

	infoCurrencyCmd.Flags().Uint64Var(&currencyID, "currency", 0, "ID of the sub-currency to look up")
	infoCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address of the currency creator")
	infoCurrencyCmd.MarkFlagRequired("currency")
	infoCurrencyCmd.MarkFlagRequired("creator")
}

var currencyCmd = &cobra.Command{
	Use:   "currency",
	Short: "Manage sub-currencies",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var createCurrencyCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a sub-currency",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		creator := accountList.getAddressByName(currencyCreator)

		creatorRaw, err := basics.UnmarshalChecksumAddress(creator)
		if err != nil {
			reportErrorf("Cannot parse address %s: %s", creator, err)
		}

		var tx transactions.Transaction
		tx.Type = protocol.CurrencyConfigTx
		tx.CurrencyParams = basics.CurrencyParams{
			Total:         currencyTotal,
			DefaultFrozen: currencyFrozen,
			Manager:       creatorRaw,
			Reserve:       creatorRaw,
			Freeze:        creatorRaw,
			Clawback:      creatorRaw,
		}
		if len(currencyUnitName) > len(tx.CurrencyParams.UnitName) {
			reportErrorf("Currency unit name %s too long (max %d bytes)", currencyUnitName, len(tx.CurrencyParams.UnitName))
		}
		copy(tx.CurrencyParams.UnitName[:], []byte(currencyUnitName))

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
			err = writeTxnToFile(client, false, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var destroyCurrencyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy a sub-currency",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

		if currencyManager == "" {
			currencyManager = currencyCreator
		}

		creator := accountList.getAddressByName(currencyCreator)
		manager := accountList.getAddressByName(currencyManager)

		creatorRaw, err := basics.UnmarshalChecksumAddress(creator)
		if err != nil {
			reportErrorf("Cannot parse address %s: %s", creator, err)
		}

		var tx transactions.Transaction
		tx.Type = protocol.CurrencyConfigTx
		tx.ConfigCurrency = basics.CurrencyID{
			Creator: creatorRaw,
			Index:   currencyID,
		}

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
			err = writeTxnToFile(client, false, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var configCurrencyCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure a sub-currency",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

		if currencyManager == "" {
			currencyManager = currencyCreator
		}

		creator := accountList.getAddressByName(currencyCreator)
		manager := accountList.getAddressByName(currencyManager)

		creatorRaw, err := basics.UnmarshalChecksumAddress(creator)
		if err != nil {
			reportErrorf("Cannot parse address %s: %s", creator, err)
		}

		// Fetch the current state, to fill in as a template
		current, err := client.AccountInformation(creator)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		params, ok := current.CurrencyParams[currencyID]
		if !ok {
			reportErrorf("Currency ID %d not found in account %s", currencyID, creator)
		}

		var tx transactions.Transaction
		tx.Type = protocol.CurrencyConfigTx
		tx.ConfigCurrency = basics.CurrencyID{
			Creator: creatorRaw,
			Index:   currencyID,
		}

		if cmd.Flags().Changed("new-manager") {
			tx.CurrencyParams.Manager, err = basics.UnmarshalChecksumAddress(currencyNewManager)
		} else {
			tx.CurrencyParams.Manager, err = basics.UnmarshalChecksumAddress(params.ManagerAddr)
		}
		if err != nil {
			reportErrorf("Cannot parse address: %s", err)
		}

		if cmd.Flags().Changed("new-reserve") {
			tx.CurrencyParams.Reserve, err = basics.UnmarshalChecksumAddress(currencyNewReserve)
		} else {
			tx.CurrencyParams.Reserve, err = basics.UnmarshalChecksumAddress(params.ReserveAddr)
		}
		if err != nil {
			reportErrorf("Cannot parse address: %s", err)
		}

		if cmd.Flags().Changed("new-freeze") {
			tx.CurrencyParams.Freeze, err = basics.UnmarshalChecksumAddress(currencyNewFreezer)
		} else {
			tx.CurrencyParams.Freeze, err = basics.UnmarshalChecksumAddress(params.FreezeAddr)
		}
		if err != nil {
			reportErrorf("Cannot parse address: %s", err)
		}

		if cmd.Flags().Changed("new-clawback") {
			tx.CurrencyParams.Clawback, err = basics.UnmarshalChecksumAddress(currencyNewClawback)
		} else {
			tx.CurrencyParams.Clawback, err = basics.UnmarshalChecksumAddress(params.ClawbackAddr)
		}
		if err != nil {
			reportErrorf("Cannot parse address: %s", err)
		}

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
			err = writeTxnToFile(client, false, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var sendCurrencyCmd = &cobra.Command{
	Use:   "send",
	Short: "Transfer sub-currencies",
	Long:  "Transfer sub-currency holdings.  Use a zero self-transfer to add a sub-currency to an account in the first place.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)

		// Check if from was specified, else use default
		if account == "" {
			account = accountList.getDefaultAccount()
		}

		sender := accountList.getAddressByName(account)
		toAddressResolved := accountList.getAddressByName(toAddress)
		creatorResolved := accountList.getAddressByName(currencyCreator)

		var err error
		var tx transactions.Transaction
		tx.Type = protocol.CurrencyTransferTx
		tx.CurrencyAmount = amount
		tx.XferCurrency = basics.CurrencyID{
			Index: currencyID,
		}

		tx.XferCurrency.Creator, err = basics.UnmarshalChecksumAddress(creatorResolved)
		if err != nil {
			reportErrorf("Cannot parse currency creator %s: %s", creatorResolved, err)
		}

		tx.CurrencyReceiver, err = basics.UnmarshalChecksumAddress(toAddressResolved)
		if err != nil {
			reportErrorf("Cannot parse recipient %s: %s", toAddressResolved, err)
		}

		if closeToAddress != "" {
			closeToAddressResolved := accountList.getAddressByName(closeToAddress)
			tx.CurrencyCloseTo, err = basics.UnmarshalChecksumAddress(closeToAddressResolved)
			if err != nil {
				reportErrorf("Cannot parse close address %s: %s", closeToAddressResolved, err)
			}
		}

		client := ensureFullClient(dataDir)
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
			err = writeTxnToFile(client, false, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var infoCurrencyCmd = &cobra.Command{
	Use:   "info",
	Short: "Look up current parameters for a sub-currency",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		creator := accountList.getAddressByName(currencyCreator)

		response, err := client.AccountInformation(creator)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		params, ok := response.CurrencyParams[currencyID]
		if !ok {
			reportErrorf("Currency ID %d not found in account %s", currencyID, creator)
		}

		reserve := response
		if params.ReserveAddr != "" {
			reserve, err = client.AccountInformation(params.ReserveAddr)
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}
		}

		fmt.Printf("Currency ID:      %d\n", currencyID)
		fmt.Printf("Creator:          %s\n", params.Creator)
		fmt.Printf("Unit name:        %s\n", params.UnitName)
		fmt.Printf("Maximum issue:    %d %s\n", params.Total, params.UnitName)
		fmt.Printf("Reserve amount:   %d %s\n", reserve.Currencies[currencyID].Amount, params.UnitName)
		fmt.Printf("Issued:           %d %s\n", params.Total-reserve.Currencies[currencyID].Amount, params.UnitName)
		fmt.Printf("Default frozen:   %v\n", params.DefaultFrozen)
		fmt.Printf("Manager address:  %s\n", params.ManagerAddr)
		fmt.Printf("Reserve address:  %s\n", params.ReserveAddr)
		fmt.Printf("Freeze address:   %s\n", params.FreezeAddr)
		fmt.Printf("Clawback address: %s\n", params.ClawbackAddr)
	},
}
