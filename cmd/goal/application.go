// Copyright (C) 2019-2021 Algorand, Inc.
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
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
)

var (
	appIdx     uint64
	appCreator string

	approvalProgFile string
	clearProgFile    string

	approvalProgRawFile string
	clearProgRawFile    string

	createOnCompletion string

	localSchemaUints      uint64
	localSchemaByteSlices uint64

	globalSchemaUints      uint64
	globalSchemaByteSlices uint64

	// Cobra only has a slice helper for uint, not uint64, so we'll parse
	// uint64s from strings for now. 4bn transactions and using a 32-bit
	// platform seems not so far-fetched?
	foreignApps    []string
	foreignAssets  []string
	appStrAccounts []string

	appArgs          []string
	appInputFilename string

	fetchLocal  bool
	fetchGlobal bool
	guessFormat bool
)

func init() {
	appCmd.AddCommand(createAppCmd)
	appCmd.AddCommand(deleteAppCmd)
	appCmd.AddCommand(updateAppCmd)
	appCmd.AddCommand(callAppCmd)
	appCmd.AddCommand(optInAppCmd)
	appCmd.AddCommand(closeOutAppCmd)
	appCmd.AddCommand(clearAppCmd)
	appCmd.AddCommand(readStateAppCmd)
	appCmd.AddCommand(infoAppCmd)

	appCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")
	appCmd.PersistentFlags().StringSliceVar(&appArgs, "app-arg", nil, "Args to encode for application transactions (all will be encoded to a byte slice). For ints, use the form 'int:1234'. For raw bytes, use the form 'b64:A=='. For printable strings, use the form 'str:hello'. For addresses, use the form 'addr:XYZ...'.")
	appCmd.PersistentFlags().StringSliceVar(&foreignApps, "foreign-app", nil, "Indexes of other apps whose global state is read in this transaction")
	appCmd.PersistentFlags().StringSliceVar(&foreignAssets, "foreign-asset", nil, "Indexes of assets whose parameters are read in this transaction")
	appCmd.PersistentFlags().StringSliceVar(&appStrAccounts, "app-account", nil, "Accounts that may be accessed from application logic")
	appCmd.PersistentFlags().StringVarP(&appInputFilename, "app-input", "i", "", "JSON file containing encoded arguments and inputs (mutually exclusive with app-arg-b64 and app-account)")

	appCmd.PersistentFlags().StringVar(&approvalProgFile, "approval-prog", "", "(Uncompiled) TEAL assembly program filename for approving/rejecting transactions")
	appCmd.PersistentFlags().StringVar(&clearProgFile, "clear-prog", "", "(Uncompiled) TEAL assembly program filename for updating application state when a user clears their local state")

	appCmd.PersistentFlags().StringVar(&approvalProgRawFile, "approval-prog-raw", "", "Compiled TEAL program filename for approving/rejecting transactions")
	appCmd.PersistentFlags().StringVar(&clearProgRawFile, "clear-prog-raw", "", "Compiled TEAL program filename for updating application state when a user clears their local state")

	createAppCmd.Flags().Uint64Var(&globalSchemaUints, "global-ints", 0, "Maximum number of integer values that may be stored in the global key/value store. Immutable.")
	createAppCmd.Flags().Uint64Var(&globalSchemaByteSlices, "global-byteslices", 0, "Maximum number of byte slices that may be stored in the global key/value store. Immutable.")
	createAppCmd.Flags().Uint64Var(&localSchemaUints, "local-ints", 0, "Maximum number of integer values that may be stored in local (per-account) key/value stores for this app. Immutable.")
	createAppCmd.Flags().Uint64Var(&localSchemaByteSlices, "local-byteslices", 0, "Maximum number of byte slices that may be stored in local (per-account) key/value stores for this app. Immutable.")
	createAppCmd.Flags().StringVar(&appCreator, "creator", "", "Account to create the application")
	createAppCmd.Flags().StringVar(&createOnCompletion, "on-completion", "NoOp", "OnCompletion action for application transaction")

	callAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to call app from")
	optInAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to opt in")
	closeOutAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to opt out")
	clearAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to clear app state for")
	deleteAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to send delete transaction from")
	readStateAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to fetch state from")
	updateAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to send update transaction from")

	// Can't use PersistentFlags on the root because for some reason marking
	// a root command as required with MarkPersistentFlagRequired isn't
	// working
	callAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	optInAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	closeOutAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	clearAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	deleteAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	readStateAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	updateAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	infoAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")

	// Add common transaction flags to all txn-generating app commands
	addTxnFlags(createAppCmd)
	addTxnFlags(deleteAppCmd)
	addTxnFlags(updateAppCmd)
	addTxnFlags(callAppCmd)
	addTxnFlags(optInAppCmd)
	addTxnFlags(closeOutAppCmd)
	addTxnFlags(clearAppCmd)

	readStateAppCmd.Flags().BoolVar(&fetchLocal, "local", false, "Fetch account-specific state for this application. `--from` address is required when using this flag")
	readStateAppCmd.Flags().BoolVar(&fetchGlobal, "global", false, "Fetch global state for this application.")
	readStateAppCmd.Flags().BoolVar(&guessFormat, "guess-format", false, "Format application state using heuristics to guess data encoding.")

	createAppCmd.MarkFlagRequired("creator")
	createAppCmd.MarkFlagRequired("global-ints")
	createAppCmd.MarkFlagRequired("global-byteslices")
	createAppCmd.MarkFlagRequired("local-ints")
	createAppCmd.MarkFlagRequired("local-byteslices")

	optInAppCmd.MarkFlagRequired("app-id")
	optInAppCmd.MarkFlagRequired("from")

	callAppCmd.MarkFlagRequired("app-id")
	callAppCmd.MarkFlagRequired("from")

	closeOutAppCmd.MarkFlagRequired("app-id")
	closeOutAppCmd.MarkFlagRequired("from")

	clearAppCmd.MarkFlagRequired("app-id")
	clearAppCmd.MarkFlagRequired("from")

	deleteAppCmd.MarkFlagRequired("app-id")
	deleteAppCmd.MarkFlagRequired("from")

	updateAppCmd.MarkFlagRequired("app-id")
	updateAppCmd.MarkFlagRequired("from")

	readStateAppCmd.MarkFlagRequired("app-id")

	infoAppCmd.MarkFlagRequired("app-id")
}

type appCallArg struct {
	Encoding string `codec:"encoding"`
	Value    string `codec:"value"`
}

type appCallInputs struct {
	Accounts      []string     `codec:"accounts"`
	ForeignApps   []uint64     `codec:"foreignapps"`
	ForeignAssets []uint64     `codec:"foreignassets"`
	Args          []appCallArg `codec:"args"`
}

func stringsToUint64(strs []string) []uint64 {
	out := make([]uint64, len(strs))
	for i, idstr := range strs {
		parsed, err := strconv.ParseUint(idstr, 10, 64)
		if err != nil {
			reportErrorf("Could not parse foreign app id: %v", err)
		}
		out[i] = parsed
	}
	return out
}

func getForeignAssets() []uint64 {
	return stringsToUint64(foreignAssets)
}

func getForeignApps() []uint64 {
	return stringsToUint64(foreignApps)
}

func parseAppArg(arg appCallArg) (rawValue []byte, parseErr error) {
	switch arg.Encoding {
	case "str", "string":
		rawValue = []byte(arg.Value)
	case "int", "integer":
		num, err := strconv.ParseUint(arg.Value, 10, 64)
		if err != nil {
			parseErr = fmt.Errorf("Could not parse uint64 from string (%s): %v", arg.Value, err)
			return
		}
		ibytes := make([]byte, 8)
		binary.BigEndian.PutUint64(ibytes, num)
		rawValue = ibytes
	case "addr", "address":
		addr, err := basics.UnmarshalChecksumAddress(arg.Value)
		if err != nil {
			parseErr = fmt.Errorf("Could not unmarshal checksummed address from string (%s): %v", arg.Value, err)
			return
		}
		rawValue = addr[:]
	case "b32", "base32", "byte base32":
		data, err := base32.StdEncoding.DecodeString(arg.Value)
		if err != nil {
			parseErr = fmt.Errorf("Could not decode base32-encoded string (%s): %v", arg.Value, err)
			return
		}
		rawValue = data
	case "b64", "base64", "byte base64":
		data, err := base64.StdEncoding.DecodeString(arg.Value)
		if err != nil {
			parseErr = fmt.Errorf("Could not decode base64-encoded string (%s): %v", arg.Value, err)
			return
		}
		rawValue = data
	default:
		parseErr = fmt.Errorf("Unknown encoding: %s", arg.Encoding)
	}
	return
}

func parseAppInputs(inputs appCallInputs) (args [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64) {
	accounts = inputs.Accounts
	foreignApps = inputs.ForeignApps
	foreignAssets = inputs.ForeignAssets
	args = make([][]byte, len(inputs.Args))
	for i, arg := range inputs.Args {
		rawValue, err := parseAppArg(arg)
		if err != nil {
			reportErrorf("Could not decode input at index %d: %v", i, err)
		}
		args[i] = rawValue
	}
	return
}

func processAppInputFile() (args [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64) {
	var inputs appCallInputs
	f, err := os.Open(appInputFilename)
	if err != nil {
		reportErrorf("Could not open app input JSON file: %v", err)
	}

	dec := protocol.NewJSONDecoder(f)
	err = dec.Decode(&inputs)
	if err != nil {
		reportErrorf("Could not decode app input JSON file: %v", err)
	}

	return parseAppInputs(inputs)
}

func getAppInputs() (args [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64) {
	if (appArgs != nil || appStrAccounts != nil || foreignApps != nil) && appInputFilename != "" {
		reportErrorf("Cannot specify both command-line arguments/accounts and JSON input filename")
	}
	if appInputFilename != "" {
		return processAppInputFile()
	}

	var encodedArgs []appCallArg
	for _, arg := range appArgs {
		encodingValue := strings.SplitN(arg, ":", 2)
		if len(encodingValue) != 2 {
			reportErrorf("all arguments should be of the form 'encoding:value'")
		}
		encodedArg := appCallArg{
			Encoding: encodingValue[0],
			Value:    encodingValue[1],
		}
		encodedArgs = append(encodedArgs, encodedArg)
	}

	inputs := appCallInputs{
		Accounts:      appStrAccounts,
		ForeignApps:   getForeignApps(),
		ForeignAssets: getForeignAssets(),
		Args:          encodedArgs,
	}

	return parseAppInputs(inputs)
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

func mustParseOnCompletion(ocString string) (oc transactions.OnCompletion) {
	switch strings.ToLower(ocString) {
	case "noop":
		return transactions.NoOpOC
	case "optin":
		return transactions.OptInOC
	case "closeout":
		return transactions.CloseOutOC
	case "clearstate":
		return transactions.ClearStateOC
	case "updateapplication":
		return transactions.UpdateApplicationOC
	case "deleteapplication":
		return transactions.DeleteApplicationOC
	default:
		reportErrorf("unknown value for --on-completion: %s (possible values: {NoOp, OptIn, CloseOut, ClearState, UpdateApplication, DeleteApplication})", ocString)
		return
	}
}

func mustParseProgArgs() (approval []byte, clear []byte) {
	// Ensure we don't have ambiguous or all empty args
	if (approvalProgFile == "") == (approvalProgRawFile == "") {
		reportErrorf(errorApprovProgArgsRequired)
	}
	if (clearProgFile == "") == (clearProgRawFile == "") {
		reportErrorf(errorClearProgArgsRequired)
	}

	if approvalProgFile != "" {
		approval = assembleFile(approvalProgFile)
	} else {
		approval = mustReadFile(approvalProgRawFile)
	}

	if clearProgFile != "" {
		clear = assembleFile(clearProgFile)
	} else {
		clear = mustReadFile(clearProgRawFile)
	}

	return
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
		approvalProg, clearProg := mustParseProgArgs()
		onCompletion := mustParseOnCompletion(createOnCompletion)
		appArgs, appAccounts, foreignApps, foreignAssets := getAppInputs()

		switch onCompletion {
		case transactions.CloseOutOC, transactions.ClearStateOC:
			reportWarnf("'--on-completion %s' may be ill-formed for 'goal app create'", createOnCompletion)
		}

		tx, err := client.MakeUnsignedAppCreateTx(onCompletion, approvalProg, clearProg, globalSchema, localSchema, appArgs, appAccounts, foreignApps, foreignAssets)
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

		if outFilename == "" {
			// Broadcast
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			signedTxn, err := client.SignTransactionWithWallet(wh, pw, tx)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			txid, err := client.BroadcastTransaction(signedTxn)
			if err != nil {
				reportErrorf(errorBroadcastingTX, err)
			}

			reportInfof("Attempting to create app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), crypto.HashObj(logic.Program(clearProg)))
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid, lv)
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
			if dumpForDryrun {
				// Write dryrun data to file
				proto, _ := getProto(protoVersion)
				data, err := libgoal.MakeDryrunStateBytes(client, tx, []transactions.SignedTxn{}, string(proto), dumpForDryrunFormat.String())
				if err != nil {
					reportErrorf(err.Error())
				}
				writeFile(outFilename, data, 0600)
			} else {
				// Write transaction to file
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		}
	},
}

var updateAppCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an application's programs",
	Long:  `Issue a transaction that updates an application's ApprovalProgram and ClearStateProgram`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Parse transaction parameters
		approvalProg, clearProg := mustParseProgArgs()
		appArgs, appAccounts, foreignApps, foreignAssets := getAppInputs()

		tx, err := client.MakeUnsignedAppUpdateTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets, approvalProg, clearProg)
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

			reportInfof("Attempting to update app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), crypto.HashObj(logic.Program(clearProg)))
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid, lv)
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
			if dumpForDryrun {
				// Write dryrun data to file
				proto, _ := getProto(protoVersion)
				data, err := libgoal.MakeDryrunStateBytes(client, tx, []transactions.SignedTxn{}, string(proto), dumpForDryrunFormat.String())
				if err != nil {
					reportErrorf(err.Error())
				}
				writeFile(outFilename, data, 0600)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
				if err != nil {
					reportErrorf(err.Error())
				}
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
		appArgs, appAccounts, foreignApps, foreignAssets := getAppInputs()

		tx, err := client.MakeUnsignedAppOptInTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets)
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
				err = waitForCommit(client, txid, lv)
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
			if dumpForDryrun {
				// Write dryrun data to file
				proto, _ := getProto(protoVersion)
				data, err := libgoal.MakeDryrunStateBytes(client, tx, []transactions.SignedTxn{}, string(proto), dumpForDryrunFormat.String())
				if err != nil {
					reportErrorf(err.Error())
				}
				writeFile(outFilename, data, 0600)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
				if err != nil {
					reportErrorf(err.Error())
				}
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
		appArgs, appAccounts, foreignApps, foreignAssets := getAppInputs()

		tx, err := client.MakeUnsignedAppCloseOutTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets)
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
				err = waitForCommit(client, txid, lv)
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
			if dumpForDryrun {
				// Write dryrun data to file
				proto, _ := getProto(protoVersion)
				data, err := libgoal.MakeDryrunStateBytes(client, tx, []transactions.SignedTxn{}, string(proto), dumpForDryrunFormat.String())
				if err != nil {
					reportErrorf(err.Error())
				}
				writeFile(outFilename, data, 0600)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
				if err != nil {
					reportErrorf(err.Error())
				}
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
		appArgs, appAccounts, foreignApps, foreignAssets := getAppInputs()

		tx, err := client.MakeUnsignedAppClearStateTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets)
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
				err = waitForCommit(client, txid, lv)
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
			if dumpForDryrun {
				// Write dryrun data to file
				proto, _ := getProto(protoVersion)
				data, err := libgoal.MakeDryrunStateBytes(client, tx, []transactions.SignedTxn{}, string(proto), dumpForDryrunFormat.String())
				if err != nil {
					reportErrorf(err.Error())
				}
				writeFile(outFilename, data, 0600)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
				if err != nil {
					reportErrorf(err.Error())
				}
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
		appArgs, appAccounts, foreignApps, foreignAssets := getAppInputs()

		tx, err := client.MakeUnsignedAppNoOpTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets)
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
				err = waitForCommit(client, txid, lv)
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
			if dumpForDryrun {
				// Write dryrun data to file
				proto, _ := getProto(protoVersion)
				data, err := libgoal.MakeDryrunStateBytes(client, tx, []transactions.SignedTxn{}, string(proto), dumpForDryrunFormat.String())
				if err != nil {
					reportErrorf(err.Error())
				}
				writeFile(outFilename, data, 0600)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		}
	},
}

var deleteAppCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete an application",
	Long:  `Delete an application, removing the global state and other application parameters from the creator's account`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Parse transaction parameters
		appArgs, appAccounts, foreignApps, foreignAssets := getAppInputs()

		tx, err := client.MakeUnsignedAppDeleteTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets)
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
				err = waitForCommit(client, txid, lv)
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
			if dumpForDryrun {
				// Write dryrun data to file
				proto, _ := getProto(protoVersion)
				data, err := libgoal.MakeDryrunStateBytes(client, tx, []transactions.SignedTxn{}, string(proto), dumpForDryrunFormat.String())
				if err != nil {
					reportErrorf(err.Error())
				}
				writeFile(outFilename, data, 0600)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		}
	},
}

var readStateAppCmd = &cobra.Command{
	Use:   "read",
	Short: "Read local or global state for an application",
	Long:  `Read global or local (account-specific) state for an application`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Ensure exactly one of --local or --global is specified
		if fetchLocal == fetchGlobal {
			reportErrorf(errorLocalGlobal)
		}

		// If fetching local state, ensure account is specified
		if fetchLocal && account == "" {
			reportErrorf(errorLocalStateRequiresAccount)
		}

		if fetchLocal {
			// Fetching local state. Get account information
			ad, err := client.AccountData(account)
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			// Get application local state
			local, ok := ad.AppLocalStates[basics.AppIndex(appIdx)]
			if !ok {
				reportErrorf(errorAccountNotOptedInToApp, account, appIdx)
			}

			kv := local.KeyValue
			if guessFormat {
				kv = heuristicFormat(kv)
			}

			// Encode local state to json, print, and exit
			enc := protocol.EncodeJSON(kv)

			// Print to stdout
			os.Stdout.Write(enc)
			return
		}

		if fetchGlobal {
			// Fetching global state. Get application creator
			app, err := client.ApplicationInformation(appIdx)
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			// Get creator information
			ad, err := client.AccountData(app.Params.Creator)
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			// Get app params
			params, ok := ad.AppParams[basics.AppIndex(appIdx)]
			if !ok {
				reportErrorf(errorNoSuchApplication, appIdx)
			}

			kv := params.GlobalState
			if guessFormat {
				kv = heuristicFormat(kv)
			}

			// Encode global state to json, print, and exit
			enc := protocol.EncodeJSON(kv)

			// Print to stdout
			os.Stdout.Write(enc)
			return
		}

		// Should be unreachable
		return
	},
}

var infoAppCmd = &cobra.Command{
	Use:   "info",
	Short: "Look up current parameters for an application",
	Long:  `Look up application information stored on the network, such as program hash.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		meta, err := client.ApplicationInformation(appIdx)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		params := meta.Params

		gsch := params.GlobalStateSchema
		lsch := params.LocalStateSchema

		fmt.Printf("Application ID:        %d\n", appIdx)
		fmt.Printf("Creator:               %v\n", params.Creator)
		fmt.Printf("Approval hash:         %v\n", basics.Address(logic.HashProgram(params.ApprovalProgram)))
		fmt.Printf("Clear hash:            %v\n", basics.Address(logic.HashProgram(params.ClearStateProgram)))

		if gsch != nil {
			fmt.Printf("Max global byteslices: %d\n", gsch.NumByteSlice)
			fmt.Printf("Max global integers:   %d\n", gsch.NumUint)
		}

		if lsch != nil {
			fmt.Printf("Max local byteslices:  %d\n", lsch.NumByteSlice)
			fmt.Printf("Max local integers:    %d\n", lsch.NumUint)
		}
	},
}
