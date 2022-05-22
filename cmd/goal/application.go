// Copyright (C) 2019-2022 Algorand, Inc.
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
	"bytes"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	apiclient "github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/abi"
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

	method           string
	methodArgs       []string
	methodCreatesApp bool

	approvalProgRawFile string
	clearProgRawFile    string

	extraPages uint32

	onCompletion string

	localSchemaUints      uint64
	localSchemaByteSlices uint64

	globalSchemaUints      uint64
	globalSchemaByteSlices uint64

	// Cobra only has a slice helper for uint, not uint64, so we'll parse
	// uint64s from strings for now. 4bn transactions and using a 32-bit
	// platform seems not so far-fetched?
	foreignApps    []string
	foreignAssets  []string
	appBoxes       []string // parse these as we do app args, with optional number and comma in front
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
	appCmd.AddCommand(methodAppCmd)

	appCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")
	appCmd.PersistentFlags().StringArrayVar(&appArgs, "app-arg", nil, "Args to encode for application transactions (all will be encoded to a byte slice). For ints, use the form 'int:1234'. For raw bytes, use the form 'b64:A=='. For printable strings, use the form 'str:hello'. For addresses, use the form 'addr:XYZ...'.")
	appCmd.PersistentFlags().StringSliceVar(&foreignApps, "foreign-app", nil, "Indexes of other apps whose global state is read in this transaction")
	appCmd.PersistentFlags().StringSliceVar(&foreignAssets, "foreign-asset", nil, "Indexes of assets whose parameters are read in this transaction")
	appCmd.PersistentFlags().StringArrayVar(&appBoxes, "box", nil, "Boxes that may be accessed by this transaction. Use the same form as app-arg to name the box, preceded by an optional app-id and comma. No app-id indicates the box is accessible by the app being called.")
	appCmd.PersistentFlags().StringSliceVar(&appStrAccounts, "app-account", nil, "Accounts that may be accessed from application logic")
	appCmd.PersistentFlags().StringVarP(&appInputFilename, "app-input", "i", "", "JSON file containing encoded arguments and inputs (mutually exclusive with app-arg, app-account, foreign-app, foreign-asset, and box)")

	appCmd.PersistentFlags().StringVar(&approvalProgFile, "approval-prog", "", "(Uncompiled) TEAL assembly program filename for approving/rejecting transactions")
	appCmd.PersistentFlags().StringVar(&clearProgFile, "clear-prog", "", "(Uncompiled) TEAL assembly program filename for updating application state when a user clears their local state")

	appCmd.PersistentFlags().StringVar(&approvalProgRawFile, "approval-prog-raw", "", "Compiled TEAL program filename for approving/rejecting transactions")
	appCmd.PersistentFlags().StringVar(&clearProgRawFile, "clear-prog-raw", "", "Compiled TEAL program filename for updating application state when a user clears their local state")

	createAppCmd.Flags().Uint64Var(&globalSchemaUints, "global-ints", 0, "Maximum number of integer values that may be stored in the global key/value store. Immutable.")
	createAppCmd.Flags().Uint64Var(&globalSchemaByteSlices, "global-byteslices", 0, "Maximum number of byte slices that may be stored in the global key/value store. Immutable.")
	createAppCmd.Flags().Uint64Var(&localSchemaUints, "local-ints", 0, "Maximum number of integer values that may be stored in local (per-account) key/value stores for this app. Immutable.")
	createAppCmd.Flags().Uint64Var(&localSchemaByteSlices, "local-byteslices", 0, "Maximum number of byte slices that may be stored in local (per-account) key/value stores for this app. Immutable.")
	createAppCmd.Flags().StringVar(&appCreator, "creator", "", "Account to create the application")
	createAppCmd.Flags().StringVar(&onCompletion, "on-completion", "NoOp", "OnCompletion action for application transaction")
	createAppCmd.Flags().Uint32Var(&extraPages, "extra-pages", 0, "Additional program space for supporting larger TEAL assembly program. A maximum of 3 extra pages is allowed. A page is 1024 bytes.")

	callAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to call app from")
	optInAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to opt in")
	closeOutAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to opt out")
	clearAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to clear app state for")
	deleteAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to send delete transaction from")
	readStateAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to fetch state from")
	updateAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to send update transaction from")
	methodAppCmd.Flags().StringVarP(&account, "from", "f", "", "Account to call method from")

	methodAppCmd.Flags().StringVar(&method, "method", "", "Method to be called")
	methodAppCmd.Flags().StringArrayVar(&methodArgs, "arg", nil, "Args to pass in for calling a method")
	methodAppCmd.Flags().StringVar(&onCompletion, "on-completion", "NoOp", "OnCompletion action for application transaction")
	methodAppCmd.Flags().BoolVar(&methodCreatesApp, "create", false, "Create an application in this method call")
	methodAppCmd.Flags().Uint64Var(&globalSchemaUints, "global-ints", 0, "Maximum number of integer values that may be stored in the global key/value store. Immutable, only valid when passed with --create.")
	methodAppCmd.Flags().Uint64Var(&globalSchemaByteSlices, "global-byteslices", 0, "Maximum number of byte slices that may be stored in the global key/value store. Immutable, only valid when passed with --create.")
	methodAppCmd.Flags().Uint64Var(&localSchemaUints, "local-ints", 0, "Maximum number of integer values that may be stored in local (per-account) key/value stores for this app. Immutable, only valid when passed with --create.")
	methodAppCmd.Flags().Uint64Var(&localSchemaByteSlices, "local-byteslices", 0, "Maximum number of byte slices that may be stored in local (per-account) key/value stores for this app. Immutable, only valid when passed with --create.")
	methodAppCmd.Flags().Uint32Var(&extraPages, "extra-pages", 0, "Additional program space for supporting larger TEAL assembly program. A maximum of 3 extra pages is allowed. A page is 1024 bytes. Only valid when passed with --create.")

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
	methodAppCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")

	// Add common transaction flags to all txn-generating app commands
	addTxnFlags(createAppCmd)
	addTxnFlags(deleteAppCmd)
	addTxnFlags(updateAppCmd)
	addTxnFlags(callAppCmd)
	addTxnFlags(optInAppCmd)
	addTxnFlags(closeOutAppCmd)
	addTxnFlags(clearAppCmd)
	addTxnFlags(methodAppCmd)

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

	methodAppCmd.MarkFlagRequired("method")    // nolint:errcheck // follow previous required flag format
	methodAppCmd.MarkFlagRequired("from")      // nolint:errcheck
	methodAppCmd.Flags().MarkHidden("app-arg") // nolint:errcheck
}

type appCallBytes struct {
	Encoding string `codec:"encoding"`
	Value    string `codec:"value"`
}

func newAppCallBytes(arg string) appCallBytes {
	parts := strings.SplitN(arg, ":", 2)
	if len(parts) != 2 {
		reportErrorf("all arguments and box names should be of the form 'encoding:value'")
	}
	return appCallBytes{
		Encoding: parts[0],
		Value:    parts[1],
	}
}

type appCallInputs struct {
	Accounts      []string       `codec:"accounts"`
	ForeignApps   []uint64       `codec:"foreignapps"`
	ForeignAssets []uint64       `codec:"foreignassets"`
	Boxes         []boxRef       `codec:"boxes"`
	Args          []appCallBytes `codec:"args"`
}

type boxRef struct {
	appId uint64       `codec:"app"`
	name  appCallBytes `codec:"name"`
}

// newBoxRef parses a command-line box ref, which is an optional appId, a comma,
// and then the same format as an app call arg.
func newBoxRef(arg string) boxRef {
	parts := strings.SplitN(arg, ":", 2)
	if len(parts) != 2 {
		reportErrorf("box refs should be of the form '[<app>,]encoding:value'")
	}
	encoding := parts[0] // tentative, may be <app>,<encoding>
	value := parts[1]
	parts = strings.SplitN(encoding, ",", 2)
	appId := uint64(0)
	if len(parts) == 2 {
		// There was a comma in the part before the ":"
		encoding = parts[1]
		var err error
		appId, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			reportErrorf("Could not parse app id in box ref: %v", err)
		}
	}
	return boxRef{
		appId: appId,
		name:  newAppCallBytes(encoding + ":" + value),
	}
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

func stringsToBoxRefs(strs []string) []boxRef {
	out := make([]boxRef, len(strs))
	for i, brstr := range strs {
		out[i] = newBoxRef(brstr)
	}
	return out
}

func (arg appCallBytes) raw() (rawValue []byte, parseErr error) {
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
	case "abi":
		typeAndValue := strings.SplitN(arg.Value, ":", 2)
		if len(typeAndValue) != 2 {
			parseErr = fmt.Errorf("Could not decode abi string (%s): should split abi-type and abi-value with colon", arg.Value)
			return
		}
		abiType, err := abi.TypeOf(typeAndValue[0])
		if err != nil {
			parseErr = fmt.Errorf("Could not decode abi type string (%s): %v", typeAndValue[0], err)
			return
		}
		value, err := abiType.UnmarshalFromJSON([]byte(typeAndValue[1]))
		if err != nil {
			parseErr = fmt.Errorf("Could not decode abi value string (%s):%v ", typeAndValue[1], err)
			return
		}
		return abiType.Encode(value)
	default:
		parseErr = fmt.Errorf("Unknown encoding: %s", arg.Encoding)
	}
	return
}

func translateBoxRefs(input []boxRef, foreignApps []uint64) []transactions.BoxRef {
	output := make([]transactions.BoxRef, len(input))
	for i, tbr := range input {
		rawName, err := tbr.name.raw()
		if err != nil {
			reportErrorf("Could not decode box name %s: %v", tbr.name, err)
		}

		index := uint64(0)
		if tbr.appId != 0 {
			found := false
			for a, id := range foreignApps {
				if tbr.appId == id {
					index = uint64(a + 1)
					found = true
					break
				}
			}
			if !found {
				reportErrorf("Box ref with appId (%d) not in foreign-apps", tbr.appId)
			}
		}
		output[i] = transactions.BoxRef{
			Index: index,
			Name:  string(rawName),
		}
	}
	return output
}

func parseAppInputs(inputs appCallInputs) (args [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64, boxes []transactions.BoxRef) {
	accounts = inputs.Accounts
	foreignApps = inputs.ForeignApps
	foreignAssets = inputs.ForeignAssets
	boxes = translateBoxRefs(inputs.Boxes, foreignApps)
	args = make([][]byte, len(inputs.Args))
	for i, arg := range inputs.Args {
		rawValue, err := arg.raw()
		if err != nil {
			reportErrorf("Could not decode input at index %d: %v", i, err)
		}
		args[i] = rawValue
	}
	return
}

func processAppInputFile() (args [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64, boxes []transactions.BoxRef) {
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

func getAppInputs() (args [][]byte, accounts []string, apps []uint64, assets []uint64, boxes []transactions.BoxRef) {
	if appInputFilename != "" {
		if appArgs != nil || appStrAccounts != nil || foreignApps != nil || foreignAssets != nil {
			reportErrorf("Cannot specify both command-line arguments/resources and JSON input filename")
		}
		return processAppInputFile()
	}

	// we need to ignore empty strings from appArgs because app-arg was
	// previously a StringSliceVar, which also does that, and some test depend
	// on it. appArgs became `StringArrayVar` in order to support abi arguments
	// which contain commas.

	var encodedArgs []appCallBytes
	for _, arg := range appArgs {
		if len(arg) > 0 {
			encodedArgs = append(encodedArgs, newAppCallBytes(arg))
		}
	}

	inputs := appCallInputs{
		Accounts:      appStrAccounts,
		ForeignApps:   stringsToUint64(foreignApps),
		ForeignAssets: stringsToUint64(foreignAssets),
		Boxes:         stringsToBoxRefs(appBoxes),
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

func getDataDirAndClient() (dataDir string, client libgoal.Client) {
	dataDir = ensureSingleDataDir()
	client = ensureFullClient(dataDir)
	return
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
		approval = assembleFile(approvalProgFile, false)
	} else {
		approval = mustReadFile(approvalProgRawFile)
	}

	if clearProgFile != "" {
		clear = assembleFile(clearProgFile, false)
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
		dataDir, client := getDataDirAndClient()

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
		onCompletionEnum := mustParseOnCompletion(onCompletion)
		appArgs, appAccounts, foreignApps, foreignAssets, boxes := getAppInputs()

		switch onCompletionEnum {
		case transactions.CloseOutOC, transactions.ClearStateOC:
			reportWarnf("'--on-completion %s' may be ill-formed for 'goal app create'", onCompletion)
		}

		tx, err := client.MakeUnsignedAppCreateTx(onCompletionEnum, approvalProg, clearProg, globalSchema, localSchema, appArgs, appAccounts, foreignApps, foreignAssets, boxes, extraPages)
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
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
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
				txn, err := waitForCommit(client, txid, lv)
				if err != nil {
					reportErrorf(err.Error())
				}
				if txn.TransactionResults != nil && txn.TransactionResults.CreatedAppIndex != 0 {
					reportInfof("Created app with app index %d", txn.TransactionResults.CreatedAppIndex)
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				// Write transaction to file
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
			if err != nil {
				reportErrorf(err.Error())
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
		dataDir, client := getDataDirAndClient()

		// Parse transaction parameters
		approvalProg, clearProg := mustParseProgArgs()
		appArgs, appAccounts, foreignApps, foreignAssets, boxes := getAppInputs()

		tx, err := client.MakeUnsignedAppUpdateTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets, boxes, approvalProg, clearProg)
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
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
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
				_, err = waitForCommit(client, txid, lv)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
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
		dataDir, client := getDataDirAndClient()

		// Parse transaction parameters
		appArgs, appAccounts, foreignApps, foreignAssets, boxes := getAppInputs()

		tx, err := client.MakeUnsignedAppOptInTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets, boxes)
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
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
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
				_, err = waitForCommit(client, txid, lv)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
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
		dataDir, client := getDataDirAndClient()

		// Parse transaction parameters
		appArgs, appAccounts, foreignApps, foreignAssets, boxes := getAppInputs()

		tx, err := client.MakeUnsignedAppCloseOutTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets, boxes)
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
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
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
				_, err = waitForCommit(client, txid, lv)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
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
		dataDir, client := getDataDirAndClient()

		// Parse transaction parameters
		appArgs, appAccounts, foreignApps, foreignAssets, boxes := getAppInputs()

		tx, err := client.MakeUnsignedAppClearStateTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets, boxes)
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
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
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
				_, err = waitForCommit(client, txid, lv)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
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
		dataDir, client := getDataDirAndClient()

		// Parse transaction parameters
		appArgs, appAccounts, foreignApps, foreignAssets, boxes := getAppInputs()

		tx, err := client.MakeUnsignedAppNoOpTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets, boxes)
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
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
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
				_, err = waitForCommit(client, txid, lv)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
			if err != nil {
				reportErrorf(err.Error())
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
		dataDir, client := getDataDirAndClient()

		// Parse transaction parameters
		appArgs, appAccounts, foreignApps, foreignAssets, boxes := getAppInputs()

		tx, err := client.MakeUnsignedAppDeleteTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets, boxes)
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
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			tx.Fee = basics.MicroAlgos{Raw: fee}
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
				_, err = waitForCommit(client, txid, lv)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)

			}
			if err != nil {
				reportErrorf(err.Error())
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
		_, client := getDataDirAndClient()

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
			ai, err := client.RawAccountApplicationInformation(account, appIdx)
			if err != nil {
				var httpError apiclient.HTTPError
				if errors.As(err, &httpError) && httpError.StatusCode == http.StatusNotFound {
					reportErrorf(errorAccountNotOptedInToApp, account, appIdx)
				}
				reportErrorf(errorRequestFail, err)
			}

			if ai.AppLocalState == nil {
				reportErrorf(errorAccountNotOptedInToApp, account, appIdx)
			}

			kv := ai.AppLocalState.KeyValue
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
			ai, err := client.RawAccountApplicationInformation(app.Params.Creator, appIdx)
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			if ai.AppParams == nil {
				reportErrorf(errorAccountNotOptedInToApp, account, appIdx)
			}

			kv := ai.AppParams.GlobalState
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
		_, client := getDataDirAndClient()

		meta, err := client.ApplicationInformation(appIdx)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		params := meta.Params

		gsch := params.GlobalStateSchema
		lsch := params.LocalStateSchema
		epp := params.ExtraProgramPages

		fmt.Printf("Application ID:        %d\n", appIdx)
		fmt.Printf("Application account:   %v\n", basics.AppIndex(appIdx).Address())
		fmt.Printf("Creator:               %v\n", params.Creator)
		fmt.Printf("Approval hash:         %v\n", basics.Address(logic.HashProgram(params.ApprovalProgram)))
		fmt.Printf("Clear hash:            %v\n", basics.Address(logic.HashProgram(params.ClearStateProgram)))

		if epp != nil {
			fmt.Printf("Extra program pages:   %d\n", *epp)
		}

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

// populateMethodCallTxnArgs parses and loads transactions from the files indicated by the values
// slice. An error will occur if the transaction does not matched the expected type, it has a nonzero
// group ID, or if it is signed by a normal signature or Msig signature (but not Lsig signature)
func populateMethodCallTxnArgs(types []string, values []string) ([]transactions.SignedTxn, error) {
	loadedTxns := make([]transactions.SignedTxn, len(values))

	for i, txFilename := range values {
		data, err := readFile(txFilename)
		if err != nil {
			return nil, fmt.Errorf(fileReadError, txFilename, err)
		}

		var txn transactions.SignedTxn
		err = protocol.Decode(data, &txn)
		if err != nil {
			return nil, fmt.Errorf(txDecodeError, txFilename, err)
		}

		if !txn.Sig.Blank() || !txn.Msig.Blank() {
			return nil, fmt.Errorf("Transaction from %s has already been signed", txFilename)
		}

		if !txn.Txn.Group.IsZero() {
			return nil, fmt.Errorf("Transaction from %s already has a group ID: %s", txFilename, txn.Txn.Group)
		}

		expectedType := types[i]
		if expectedType != abi.AnyTransactionType && txn.Txn.Type != protocol.TxType(expectedType) {
			return nil, fmt.Errorf("Transaction from %s does not match method argument type. Expected %s, got %s", txFilename, expectedType, txn.Txn.Type)
		}

		loadedTxns[i] = txn
	}

	return loadedTxns, nil
}

// populateMethodCallReferenceArgs parses reference argument types and resolves them to an index
// into the appropriate foreign array. Their placement will be as compact as possible, which means
// values will be deduplicated and any value that is the sender or the current app will not be added
// to the foreign array.
func populateMethodCallReferenceArgs(sender string, currentApp uint64, types []string, values []string, accounts *[]string, apps *[]uint64, assets *[]uint64) ([]int, error) {
	resolvedIndexes := make([]int, len(types))

	for i, value := range values {
		var resolved int

		switch types[i] {
		case abi.AccountReferenceType:
			if value == sender {
				resolved = 0
			} else {
				duplicate := false
				for j, account := range *accounts {
					if value == account {
						resolved = j + 1 // + 1 because 0 is the sender
						duplicate = true
						break
					}
				}
				if !duplicate {
					resolved = len(*accounts) + 1
					*accounts = append(*accounts, value)
				}
			}
		case abi.ApplicationReferenceType:
			appID, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("Unable to parse application ID '%s': %s", value, err)
			}
			if appID == currentApp {
				resolved = 0
			} else {
				duplicate := false
				for j, app := range *apps {
					if appID == app {
						resolved = j + 1 // + 1 because 0 is the current app
						duplicate = true
						break
					}
				}
				if !duplicate {
					resolved = len(*apps) + 1
					*apps = append(*apps, appID)
				}
			}
		case abi.AssetReferenceType:
			assetID, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("Unable to parse asset ID '%s': %s", value, err)
			}
			duplicate := false
			for j, asset := range *assets {
				if assetID == asset {
					resolved = j
					duplicate = true
					break
				}
			}
			if !duplicate {
				resolved = len(*assets)
				*assets = append(*assets, assetID)
			}
		default:
			return nil, fmt.Errorf("Unknown reference type: %s", types[i])
		}

		resolvedIndexes[i] = resolved
	}

	return resolvedIndexes, nil
}

var methodAppCmd = &cobra.Command{
	Use:   "method",
	Short: "Invoke an ABI method",
	Long:  `Invoke an ARC-4 ABI method on an App (stateful contract) with an application call transaction`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir, client := getDataDirAndClient()

		// Parse transaction parameters
		appArgsParsed, appAccounts, foreignApps, foreignAssets, boxes := getAppInputs()
		if len(appArgsParsed) > 0 {
			reportErrorf("--arg and --app-arg are mutually exclusive, do not use --app-arg")
		}

		// Construct schemas from args
		localSchema := basics.StateSchema{
			NumUint:      localSchemaUints,
			NumByteSlice: localSchemaByteSlices,
		}

		globalSchema := basics.StateSchema{
			NumUint:      globalSchemaUints,
			NumByteSlice: globalSchemaByteSlices,
		}

		onCompletionEnum := mustParseOnCompletion(onCompletion)

		if methodCreatesApp {
			if appIdx != 0 {
				reportErrorf("--app-id and --create are mutually exclusive, only provide one")
			}

			switch onCompletionEnum {
			case transactions.CloseOutOC, transactions.ClearStateOC:
				reportWarnf("'--on-completion %s' may be ill-formed for use with --create", onCompletion)
			}
		} else {
			if appIdx == 0 {
				reportErrorf("one of --app-id or --create must be provided")
			}

			if localSchema != (basics.StateSchema{}) || globalSchema != (basics.StateSchema{}) {
				reportErrorf("--global-ints, --global-byteslices, --local-ints, and --local-byteslices must only be provided with --create")
			}

			if extraPages != 0 {
				reportErrorf("--extra-pages must only be provided with --create")
			}
		}

		var approvalProg, clearProg []byte
		if methodCreatesApp || onCompletionEnum == transactions.UpdateApplicationOC {
			approvalProg, clearProg = mustParseProgArgs()
		}

		var applicationArgs [][]byte

		// insert the method selector hash
		hash := sha512.Sum512_256([]byte(method))
		applicationArgs = append(applicationArgs, hash[0:4])

		// parse down the ABI type from method signature
		_, argTypes, retTypeStr, err := abi.ParseMethodSignature(method)
		if err != nil {
			reportErrorf("cannot parse method signature: %v", err)
		}

		var retType *abi.Type
		if retTypeStr != abi.VoidReturnType {
			theRetType, err := abi.TypeOf(retTypeStr)
			if err != nil {
				reportErrorf("cannot cast %s to abi type: %v", retTypeStr, err)
			}
			retType = &theRetType
		}

		if len(methodArgs) != len(argTypes) {
			reportErrorf("incorrect number of arguments, method expected %d but got %d", len(argTypes), len(methodArgs))
		}

		var txnArgTypes []string
		var txnArgValues []string
		var basicArgTypes []string
		var basicArgValues []string
		var refArgTypes []string
		var refArgValues []string
		refArgIndexToBasicArgIndex := make(map[int]int)
		for i, argType := range argTypes {
			argValue := methodArgs[i]
			if abi.IsTransactionType(argType) {
				txnArgTypes = append(txnArgTypes, argType)
				txnArgValues = append(txnArgValues, argValue)
			} else {
				if abi.IsReferenceType(argType) {
					refArgIndexToBasicArgIndex[len(refArgTypes)] = len(basicArgTypes)
					refArgTypes = append(refArgTypes, argType)
					refArgValues = append(refArgValues, argValue)
					// treat the reference as a uint8 for encoding purposes
					argType = "uint8"
				}
				basicArgTypes = append(basicArgTypes, argType)
				basicArgValues = append(basicArgValues, argValue)
			}
		}

		refArgsResolved, err := populateMethodCallReferenceArgs(account, appIdx, refArgTypes, refArgValues, &appAccounts, &foreignApps, &foreignAssets)
		if err != nil {
			reportErrorf("error populating reference arguments: %v", err)
		}
		for i, resolved := range refArgsResolved {
			basicArgIndex := refArgIndexToBasicArgIndex[i]
			// use the foreign array index as the encoded argument value
			basicArgValues[basicArgIndex] = strconv.Itoa(resolved)
		}

		err = abi.ParseArgJSONtoByteSlice(basicArgTypes, basicArgValues, &applicationArgs)
		if err != nil {
			reportErrorf("cannot parse arguments to ABI encoding: %v", err)
		}

		txnArgs, err := populateMethodCallTxnArgs(txnArgTypes, txnArgValues)
		if err != nil {
			reportErrorf("error populating transaction arguments: %v", err)
		}

		appCallTxn, err := client.MakeUnsignedApplicationCallTx(
			appIdx, applicationArgs, appAccounts, foreignApps, foreignAssets, boxes,
			onCompletionEnum, approvalProg, clearProg, globalSchema, localSchema, extraPages)

		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		appCallTxn.Note = parseNoteField(cmd)
		appCallTxn.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf("Cannot determine last valid round: %s", err)
		}

		appCallTxn, err = client.FillUnsignedTxTemplate(account, fv, lv, fee, appCallTxn)
		if err != nil {
			reportErrorf("Cannot construct transaction: %s", err)
		}
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			appCallTxn.Fee = basics.MicroAlgos{Raw: fee}
		}

		// Compile group
		var txnGroup []transactions.Transaction
		for i := range txnArgs {
			txnGroup = append(txnGroup, txnArgs[i].Txn)
		}
		txnGroup = append(txnGroup, appCallTxn)
		if len(txnGroup) > 1 {
			// Only if transaction arguments are present, assign group ID
			groupID, err := client.GroupID(txnGroup)
			if err != nil {
				reportErrorf("Cannot assign transaction group ID: %s", err)
			}
			for i := range txnGroup {
				txnGroup[i].Group = groupID
			}
		}

		// Sign transactions
		var signedTxnGroup []transactions.SignedTxn
		shouldSign := sign || outFilename == ""
		for i, unsignedTxn := range txnGroup {
			txnFromArgs := transactions.SignedTxn{}
			if i < len(txnArgs) {
				txnFromArgs = txnArgs[i]
			}

			if !txnFromArgs.Lsig.Blank() {
				signedTxnGroup = append(signedTxnGroup, transactions.SignedTxn{
					Lsig:     txnFromArgs.Lsig,
					AuthAddr: txnFromArgs.AuthAddr,
					Txn:      unsignedTxn,
				})
				continue
			}

			signedTxn, err := createSignedTransaction(client, shouldSign, dataDir, walletName, unsignedTxn, txnFromArgs.AuthAddr)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			signedTxnGroup = append(signedTxnGroup, signedTxn)
		}

		// Output to file
		if outFilename != "" {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, signedTxnGroup, outFilename)
			} else {
				err = writeSignedTxnsToFile(signedTxnGroup, outFilename)
			}
			if err != nil {
				reportErrorf(err.Error())
			}
			return
		}

		// Broadcast
		err = client.BroadcastTransactionGroup(signedTxnGroup)
		if err != nil {
			reportErrorf(errorBroadcastingTX, err)
		}

		// Report tx details to user
		if methodCreatesApp {
			reportInfof("Attempting to create app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), crypto.HashObj(logic.Program(clearProg)))
		} else if onCompletionEnum == transactions.UpdateApplicationOC {
			reportInfof("Attempting to update app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), crypto.HashObj(logic.Program(clearProg)))
		}

		reportInfof("Issued %d transaction(s):", len(signedTxnGroup))

		// remember the final txid in this variable
		var txid string
		for _, stxn := range signedTxnGroup {
			txid = stxn.Txn.ID().String()
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", stxn.Txn.Sender, txid, stxn.Txn.Fee.Raw)
		}

		if !noWaitAfterSend {
			_, err := waitForCommit(client, txid, lv)
			if err != nil {
				reportErrorf(err.Error())
			}

			resp, err := client.PendingTransactionInformationV2(txid)
			if err != nil {
				reportErrorf(err.Error())
			}

			if methodCreatesApp && resp.ApplicationIndex != nil && *resp.ApplicationIndex != 0 {
				reportInfof("Created app with app index %d", *resp.ApplicationIndex)
			}

			if retType == nil {
				reportInfof("method %s succeeded", method)
				return
			}

			// the 4-byte prefix for logged return values, from https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0004.md#standard-format
			var abiReturnHash = []byte{0x15, 0x1f, 0x7c, 0x75}

			if resp.Logs == nil || len(*resp.Logs) == 0 {
				reportErrorf("method %s succeed but did not log a return value", method)
			}

			lastLog := (*resp.Logs)[len(*resp.Logs)-1]
			if !bytes.HasPrefix(lastLog, abiReturnHash) {
				reportErrorf("method %s succeed but did not log a return value", method)
			}

			rawReturnValue := lastLog[len(abiReturnHash):]
			decoded, err := retType.Decode(rawReturnValue)
			if err != nil {
				reportErrorf("method %s succeed but its return value could not be decoded.\nThe raw return value in hex is:%s\nThe error is: %s", method, hex.EncodeToString(rawReturnValue), err)
			}

			decodedJSON, err := retType.MarshalToJSON(decoded)
			if err != nil {
				reportErrorf("method %s succeed but its return value could not be converted to JSON.\nThe raw return value in hex is:%s\nThe error is: %s", method, hex.EncodeToString(rawReturnValue), err)
			}

			reportInfof("method %s succeeded with output: %s", method, string(decodedJSON))
		}
	},
}
