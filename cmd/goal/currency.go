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

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/libgoal"
)

var (
	numValidRounds   uint64
	currencyID       uint64
	currencyCreator  string
	currencyTotal    uint64
	currencyFrozen   bool
	currencyUnitName string
	currencyManager  string
	currencyClawback string
	currencyFreezer  string

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
	currencyCmd.AddCommand(freezeCurrencyCmd)

	createCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for creating a currency")
	createCurrencyCmd.Flags().Uint64Var(&currencyTotal, "total", 0, "Total amount of tokens for created currency")
	createCurrencyCmd.Flags().BoolVar(&currencyFrozen, "defaultfrozen", false, "Freeze or not freeze holdings by default")
	createCurrencyCmd.Flags().StringVar(&currencyUnitName, "unitname", "", "Name for the unit of currency")
	createCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	createCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	createCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	createCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	createCurrencyCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	createCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	createCurrencyCmd.MarkFlagRequired("creator")
	createCurrencyCmd.MarkFlagRequired("total")

	destroyCurrencyCmd.Flags().StringVar(&currencyManager, "manager", "", "Manager account to issue the destroy transaction (defaults to creator)")
	destroyCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for currency to destroy")
	destroyCurrencyCmd.Flags().Uint64Var(&currencyID, "currencyid", 0, "Currency ID to destroy")
	destroyCurrencyCmd.Flags().StringVar(&currencyUnitName, "currency", "", "Unit name of currency to destroy")
	destroyCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	destroyCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	destroyCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	destroyCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	destroyCurrencyCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	destroyCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	destroyCurrencyCmd.MarkFlagRequired("creator")

	configCurrencyCmd.Flags().StringVar(&currencyManager, "manager", "", "Manager account to issue the config transaction (defaults to creator)")
	configCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for currency to configure")
	configCurrencyCmd.Flags().Uint64Var(&currencyID, "currencyid", 0, "Currency ID to configure")
	configCurrencyCmd.Flags().StringVar(&currencyUnitName, "currency", "", "Unit name of currency to configure")
	configCurrencyCmd.Flags().StringVar(&currencyNewManager, "new-manager", "", "New manager address")
	configCurrencyCmd.Flags().StringVar(&currencyNewReserve, "new-reserve", "", "New reserve address")
	configCurrencyCmd.Flags().StringVar(&currencyNewFreezer, "new-freezer", "", "New freeze address")
	configCurrencyCmd.Flags().StringVar(&currencyNewClawback, "new-clawback", "", "New clawback address")
	configCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	configCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	configCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	configCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	configCurrencyCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	configCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	configCurrencyCmd.MarkFlagRequired("creator")

	sendCurrencyCmd.Flags().StringVar(&currencyClawback, "clawback", "", "Address to issue a clawback transaction from (defaults to no clawback)")
	sendCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for currency creator")
	sendCurrencyCmd.Flags().Uint64Var(&currencyID, "currencyid", 0, "ID of the currency being transferred")
	sendCurrencyCmd.Flags().StringVar(&currencyUnitName, "currency", "", "Unit name of the currency being transferred")
	sendCurrencyCmd.Flags().StringVarP(&account, "from", "f", "", "Account address to send the money from (if not specified, uses default account)")
	sendCurrencyCmd.Flags().StringVarP(&toAddress, "to", "t", "", "Address to send to money to (required)")
	sendCurrencyCmd.Flags().Uint64VarP(&amount, "amount", "a", 0, "The amount to be transferred (required), in microAlgos")
	sendCurrencyCmd.Flags().StringVarP(&closeToAddress, "close-to", "c", "", "Close currency account and send remainder to this address")
	sendCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	sendCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	sendCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	sendCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	sendCurrencyCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	sendCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	sendCurrencyCmd.MarkFlagRequired("creator")
	sendCurrencyCmd.MarkFlagRequired("to")
	sendCurrencyCmd.MarkFlagRequired("amount")

	freezeCurrencyCmd.Flags().StringVar(&currencyFreezer, "freezer", "", "Address to issue a freeze transaction from")
	freezeCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address for currency creator")
	freezeCurrencyCmd.Flags().Uint64Var(&currencyID, "currencyid", 0, "ID of the currency being frozen")
	freezeCurrencyCmd.Flags().StringVar(&currencyUnitName, "currency", "", "Unit name of the currency being frozen")
	freezeCurrencyCmd.Flags().StringVar(&account, "account", "", "Account address to freeze/unfreeze")
	freezeCurrencyCmd.Flags().BoolVar(&currencyFrozen, "freeze", false, "Freeze or unfreeze")
	freezeCurrencyCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	freezeCurrencyCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	freezeCurrencyCmd.Flags().Uint64Var(&numValidRounds, "validrounds", 0, "The number of rounds for which the transaction will be valid")
	freezeCurrencyCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Write transaction to this file")
	freezeCurrencyCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	freezeCurrencyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	freezeCurrencyCmd.MarkFlagRequired("freezer")
	freezeCurrencyCmd.MarkFlagRequired("creator")
	freezeCurrencyCmd.MarkFlagRequired("account")
	freezeCurrencyCmd.MarkFlagRequired("freeze")

	infoCurrencyCmd.Flags().Uint64Var(&currencyID, "currencyid", 0, "ID of the currency to look up")
	infoCurrencyCmd.Flags().StringVar(&currencyUnitName, "currency", "", "Unit name of the currency to look up")
	infoCurrencyCmd.Flags().StringVar(&currencyCreator, "creator", "", "Account address of the currency creator")
	infoCurrencyCmd.MarkFlagRequired("creator")
}

var currencyCmd = &cobra.Command{
	Use:   "currency",
	Short: "Manage currencies",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

func lookupCurrencyID(cmd *cobra.Command, creator string, client libgoal.Client) {
	if cmd.Flags().Changed("currencyid") && cmd.Flags().Changed("currency") {
		reportErrorf("Only one of -currencyid and -currency can be specified")
	}

	if cmd.Flags().Changed("currencyid") {
		return
	}

	if !cmd.Flags().Changed("currency") {
		reportErrorf("One of -currencyid and -currency must be specified")
	}

	response, err := client.AccountInformation(creator)
	if err != nil {
		reportErrorf(errorRequestFail, err)
	}

	nmatch := 0
	for id, params := range response.CurrencyParams {
		if params.UnitName == currencyUnitName {
			currencyID = id
			nmatch++
		}
	}

	if nmatch == 0 {
		reportErrorf("No matches for currency unit name %s in creator %s", currencyUnitName, creator)
	}

	if nmatch > 1 {
		reportErrorf("Multiple matches for currency unit name %s in creator %s", currencyUnitName, creator)
	}
}

var createCurrencyCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a currency",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		creator := accountList.getAddressByName(currencyCreator)

		tx, err := client.MakeUnsignedCurrencyCreateTx(currencyTotal, currencyFrozen, creator, creator, creator, creator, currencyUnitName)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

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

var destroyCurrencyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy a currency",
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

		lookupCurrencyID(cmd, creator, client)

		tx, err := client.MakeUnsignedCurrencyDestroyTx(creator, currencyID)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
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
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var configCurrencyCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure a currency",
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

		lookupCurrencyID(cmd, creator, client)

		var newManager, newReserve, newFreeze, newClawback *string
		if cmd.Flags().Changed("new-manager") {
			currencyNewManager = accountList.getAddressByName(currencyNewManager)
			newManager = &currencyNewManager
		}

		if cmd.Flags().Changed("new-reserve") {
			currencyNewReserve = accountList.getAddressByName(currencyNewReserve)
			newReserve = &currencyNewReserve
		}

		if cmd.Flags().Changed("new-freezer") {
			currencyNewFreezer = accountList.getAddressByName(currencyNewFreezer)
			newFreeze = &currencyNewFreezer
		}

		if cmd.Flags().Changed("new-clawback") {
			currencyNewClawback = accountList.getAddressByName(currencyNewClawback)
			newClawback = &currencyNewClawback
		}

		tx, err := client.MakeUnsignedCurrencyConfigTx(creator, currencyID, newManager, newReserve, newFreeze, newClawback)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
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
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var sendCurrencyCmd = &cobra.Command{
	Use:   "send",
	Short: "Transfer currencies",
	Long:  "Transfer currency holdings.  Use a zero self-transfer to add a currency to an account in the first place.",
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
		creatorResolved := accountList.getAddressByName(currencyCreator)

		lookupCurrencyID(cmd, creatorResolved, client)

		var senderForClawback string
		if currencyClawback != "" {
			senderForClawback = sender
			sender = accountList.getAddressByName(currencyClawback)
		}

		var closeToAddressResolved string
		if closeToAddress != "" {
			closeToAddressResolved = accountList.getAddressByName(closeToAddress)
		}

		tx, err := client.MakeUnsignedCurrencySendTx(creatorResolved, currencyID, amount, toAddressResolved, closeToAddressResolved, senderForClawback)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

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

var freezeCurrencyCmd = &cobra.Command{
	Use:   "freeze",
	Short: "Freeze currencies",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)

		freezer := accountList.getAddressByName(currencyFreezer)
		creatorResolved := accountList.getAddressByName(currencyCreator)
		accountResolved := accountList.getAddressByName(account)

		lookupCurrencyID(cmd, creatorResolved, client)

		tx, err := client.MakeUnsignedCurrencyFreezeTx(creatorResolved, currencyID, accountResolved, currencyFrozen)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

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

var infoCurrencyCmd = &cobra.Command{
	Use:   "info",
	Short: "Look up current parameters for a currency",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		accountList := makeAccountsList(dataDir)
		creator := accountList.getAddressByName(currencyCreator)

		lookupCurrencyID(cmd, creator, client)

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
