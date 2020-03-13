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
	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

var (
	appIdx     uint64
	appCreator string

	approvalProgFile string
	clearProgFile    string

	localSchemaUints      uint64
	localSchemaByteSlices uint64

	globalSchemaUints      uint64
	globalSchemaByteSlices uint64

	appAccounts []string
	appB64Args  []string
)

func init() {
	appCmd.AddCommand(createAppCmd)
	appCmd.AddCommand(deleteAppCmd)
	appCmd.AddCommand(callAppCmd)
	appCmd.AddCommand(optInAppCmd)
	appCmd.AddCommand(closeOutAppCmd)
	appCmd.AddCommand(clearAppCmd)

	appCmd.PersistentFlags().StringVarP(&txFilename, "out", "o", "", "Dump an unsigned tx to the given file. In order to dump a signed transaction, pass -s")
	appCmd.PersistentFlags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	appCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")
	appCmd.PersistentFlags().Uint64Var(&appIdx, "app-id", 0, "Asset ID")
	appCmd.PersistentFlags().StringSliceVar(&appB64Args, "app-arg-b64", nil, "Base64 encoded args for application transactions")
	appCmd.PersistentFlags().StringSliceVar(&appAccounts, "app-account", nil, "Accounts that may be accessed from application logic")

	createAppCmd.Flags().StringVar(&approvalProgFile, "approval-prog", "", "TEAL program to approve/reject transactions")
	createAppCmd.Flags().StringVar(&clearProgFile, "clear-prog", "", "TEAL program to update application state when a user clears their state")

	createAppCmd.Flags().Uint64Var(&globalSchemaUints, "global-ints", 0, "Maximum number of integer values that may be stored in the global key/value store. Immutable.")
	createAppCmd.Flags().Uint64Var(&globalSchemaByteSlices, "global-byteslices", 0, "Maximum number of byte slices that may be stored in the global key/value store. Immutable.")
	createAppCmd.Flags().Uint64Var(&localSchemaUints, "local-ints", 0, "Maximum number of integer values that may be stored in local (per-account) key/value stores for this app. Immutable.")
	createAppCmd.Flags().Uint64Var(&localSchemaByteSlices, "local-byteslices", 0, "Maximum number of byte slices that may be stored in local (per-account) key/value stores for this app. Immutable.")

	createAppCmd.Flags().StringVar(&appCreator, "creator", "", "Account to create the asset")
	callAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to call app from")
	optInAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to opt in")
	closeOutAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to opt out")
	clearAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to clear app state for")

	createAppCmd.MarkFlagRequired("creator")
	createAppCmd.MarkFlagRequired("global-ints")
	createAppCmd.MarkFlagRequired("global-byteslices")
	createAppCmd.MarkFlagRequired("local-ints")
	createAppCmd.MarkFlagRequired("local-byteslices")
	createAppCmd.MarkFlagRequired("approval-prog")
	createAppCmd.MarkFlagRequired("clear-prog")

	optInAppCmd.MarkFlagRequired("app-id")
	optInAppCmd.MarkFlagRequired("from")
}

func getAppArgs() []string {
	decoded := getB64Args(appB64Args)
	out := make([]string, len(decoded))
	for i, b := range decoded {
		out[i] = string(b)
	}
	return out
}

var appCmd = &cobra.Command{
	Use:   "app",
	Short: "Manage applications",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var createAppCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an application",
	Long:  `Issue a transaction that creates an application`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Construct schemas from args
		localSchema := basics.StateSchema{
			NumUint:      localSchemaUints,
			NumByteSlice: localSchemaByteSlices,
		}

		globalSchema := basics.StateSchema{
			NumUint:      globalSchemaUints,
			NumByteSlice: globalSchemaByteSlices,
		}

		// Parse transaction parameters
		approvalProg := string(assembleFile(approvalProgFile))
		clearProg := string(assembleFile(clearProgFile))
		appArgs := getAppArgs()

		tx, err := client.MakeUnsignedAppCreateTx(transactions.NoOpOC, approvalProg, clearProg, globalSchema, localSchema, appArgs, appAccounts)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}

		tx, err = client.FillUnsignedTxTemplate(appCreator, fv, lv, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		// Broadcast or write transaction to file
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
				// Check if we know about the transaction yet
				txn, err := client.PendingTransactionInformation(txid)
				if err != nil {
					reportErrorf("%v", err)
				}
				if txn.TransactionResults != nil && txn.TransactionResults.CreatedAppIndex != 0 {
					reportInfof("Created app with app index %d", txn.TransactionResults.CreatedAppIndex)
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

var optInAppCmd = &cobra.Command{
	Use:   "optin",
	Short: "Opt in to an application",
	Long:  `Opt an account in to an application, allocating local state in your account`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Parse transaction parameters
		appArgs := getAppArgs()

		tx, err := client.MakeUnsignedAppOptInTx(appIdx, appArgs, appAccounts)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}

		tx, err = client.FillUnsignedTxTemplate(account, fv, lv, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		// Broadcast or write transaction to file
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
				// Check if we know about the transaction yet
				_, err := client.PendingTransactionInformation(txid)
				if err != nil {
					reportErrorf("%v", err)
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

var closeOutAppCmd = &cobra.Command{
	Use:   "closeout",
	Short: "Close out of an application",
	Long:  `Close an account out of an application, removing local state from your account. The application must still exist. If it doesn't, use 'goal app clear'.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Parse transaction parameters
		appArgs := getAppArgs()

		tx, err := client.MakeUnsignedAppCloseOutTx(appIdx, appArgs, appAccounts)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}

		tx, err = client.FillUnsignedTxTemplate(account, fv, lv, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		// Broadcast or write transaction to file
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
				// Check if we know about the transaction yet
				_, err := client.PendingTransactionInformation(txid)
				if err != nil {
					reportErrorf("%v", err)
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

var clearAppCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear out an application's state in your account",
	Long:  `Remove any local state from your account associated with an application. The application does not need to exist anymore.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Parse transaction parameters
		appArgs := getAppArgs()

		tx, err := client.MakeUnsignedAppClearStateTx(appIdx, appArgs, appAccounts)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}

		tx, err = client.FillUnsignedTxTemplate(account, fv, lv, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		// Broadcast or write transaction to file
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
				// Check if we know about the transaction yet
				_, err := client.PendingTransactionInformation(txid)
				if err != nil {
					reportErrorf("%v", err)
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

var callAppCmd = &cobra.Command{
	Use:   "call",
	Short: "Call an application",
	Long:  `Call an application, invoking application-specific functionality`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Parse transaction parameters
		appArgs := getAppArgs()

		tx, err := client.MakeUnsignedAppNoOpTx(appIdx, appArgs, appAccounts)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}

		tx, err = client.FillUnsignedTxTemplate(account, fv, lv, fee, tx)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}

		// Broadcast or write transaction to file
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
				// Check if we know about the transaction yet
				_, err := client.PendingTransactionInformation(txid)
				if err != nil {
					reportErrorf("%v", err)
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

var deleteAppCmd = &cobra.Command{}
