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
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/avm-abi/abi"
	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/crypto"
	apiclient "github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
)

var (
	appIdx     basics.AppIndex
	appCreator string

	approvalProgFile string
	clearProgFile    string

	method           string
	methodArgs       []string
	methodCreatesApp bool

	approvalProgRawFile string
	clearProgRawFile    string

	extraPages uint32

	onCompletion  string
	rejectVersion uint64

	localSchemaUints      uint64
	localSchemaByteSlices uint64

	globalSchemaUints      uint64
	globalSchemaByteSlices uint64

	// Cobra only has a slice helper for uint, not uint64, so we'll parse
	// uint64s from strings for now. 4bn transactions and using a 32-bit
	// platform seems not so far-fetched?
	foreignApps    []string
	foreignAssets  []string
	appStrBoxes    []string // parse these as we do app args, with optional number and comma in front
	appStrAccounts []string

	// for these, an omitted addr is the sender. an omitted app is the called app.
	appStrHoldings []string // format: asset+addr OR asset ex: 5245+XQJEJECPWUOXSKMIC5TCSARPVGHQJIIOKHO7WTKEPPLJMKG3D7VWWID66E
	appStrLocals   []string // format: app+addr OR app OR addr

	// controls whether all these refs put into the old-style "foreign arrays" or the new-style tx.Access
	appUseAccess bool

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
	appCmd.PersistentFlags().Uint64Var(&rejectVersion, "reject-version", 0, "If set non-zero, reject for this app version or higher")
	appCmd.PersistentFlags().StringArrayVar(&appArgs, "app-arg", nil, "Args to encode for application transactions (all will be encoded to a byte slice). For ints, use the form 'int:1234'. For raw bytes, use the form 'b64:A=='. For printable strings, use the form 'str:hello'. For addresses, use the form 'addr:XYZ...'.")
	appCmd.PersistentFlags().StringSliceVar(&foreignApps, "foreign-app", nil, "Indexes of other apps whose global state is read in this transaction")
	appCmd.PersistentFlags().StringSliceVar(&foreignAssets, "foreign-asset", nil, "Indexes of assets whose parameters are read in this transaction")
	appCmd.PersistentFlags().StringArrayVar(&appStrBoxes, "box", nil, "A Box that may be accessed by this transaction. Use the same form as app-arg to name the box, preceded by an optional app-id and comma. Zero or omitted app-id indicates the box is accessible by the app being called.")
	appCmd.PersistentFlags().StringSliceVar(&appStrAccounts, "app-account", nil, "Accounts that may be accessed from application logic")
	appCmd.PersistentFlags().StringSliceVar(&appStrHoldings, "holding", nil, "A Holding that may be accessed from application logic. An asset-id followed by a plus sign and an address")
	appCmd.PersistentFlags().StringSliceVar(&appStrLocals, "local", nil, "A Local State that may be accessed from application logic. An optional app-id and a plus sign, followed by an address. Zero or omitted app-id indicates the local state for app being called.")
	appCmd.PersistentFlags().BoolVar(&appUseAccess, "access", false, "Put references into the transaction's access list, instead of foreign arrays.")
	appCmd.PersistentFlags().StringVarP(&appInputFilename, "app-input", "i", "", "JSON file containing encoded arguments and inputs (mutually exclusive with app-arg, app-account, foreign-app, foreign-asset, local, holding, and box)")

	appCmd.PersistentFlags().StringVar(&approvalProgFile, "approval-prog", "", "(Uncompiled) TEAL assembly program filename for approving/rejecting transactions")
	appCmd.PersistentFlags().StringVar(&clearProgFile, "clear-prog", "", "(Uncompiled) TEAL assembly program filename for updating application state when a user clears their local state")

	appCmd.PersistentFlags().StringVar(&approvalProgRawFile, "approval-prog-raw", "", "Compiled AVM bytecode program filename for approving/rejecting transactions")
	appCmd.PersistentFlags().StringVar(&clearProgRawFile, "clear-prog-raw", "", "Compiled AVM bytecode program filename for updating application state when a user clears their local state")

	createAppCmd.Flags().Uint64Var(&globalSchemaUints, "global-ints", 0, "Maximum number of integer values that may be stored in the global key/value store.")
	createAppCmd.Flags().Uint64Var(&globalSchemaByteSlices, "global-byteslices", 0, "Maximum number of byte slices that may be stored in the global key/value store.")
	createAppCmd.Flags().Uint64Var(&localSchemaUints, "local-ints", 0, "Maximum number of integer values that may be stored in local (per-account) key/value stores for this app. Immutable.")
	createAppCmd.Flags().Uint64Var(&localSchemaByteSlices, "local-byteslices", 0, "Maximum number of byte slices that may be stored in local (per-account) key/value stores for this app. Immutable.")
	createAppCmd.Flags().StringVar(&appCreator, "creator", "", "Account to create the application")
	createAppCmd.Flags().StringVar(&onCompletion, "on-completion", "NoOp", "OnCompletion action for application transaction")
	createAppCmd.Flags().Uint32Var(&extraPages, "extra-pages", 0, "Additional program space for supporting larger AVM bytecode program. A maximum of 3 extra pages is allowed. A page is 1024 bytes.")

	updateAppCmd.Flags().Uint64Var(&globalSchemaUints, "global-ints", 0, "Maximum number of integer values that may be stored in the global key/value store.")
	updateAppCmd.Flags().Uint64Var(&globalSchemaByteSlices, "global-byteslices", 0, "Maximum number of byte slices that may be stored in the global key/value store.")
	updateAppCmd.Flags().Uint32Var(&extraPages, "extra-pages", 0, "Additional program space for supporting larger AVM program. A maximum of 3 extra pages is allowed. A page is 1024 bytes.")

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
	methodAppCmd.Flags().Uint64Var(&rejectVersion, "reject-version", 0, "RejectVersion for application transaction")
	methodAppCmd.Flags().BoolVar(&methodCreatesApp, "create", false, "Create an application in this method call")
	methodAppCmd.Flags().Uint64Var(&globalSchemaUints, "global-ints", 0, "Maximum number of integer values that may be stored in the global key/value store. Valid when passed with --create or when updating.")
	methodAppCmd.Flags().Uint64Var(&globalSchemaByteSlices, "global-byteslices", 0, "Maximum number of byte slices that may be stored in the global key/value store. Valid when passed with --create or when updating.")
	methodAppCmd.Flags().Uint64Var(&localSchemaUints, "local-ints", 0, "Maximum number of integer values that may be stored in local (per-account) key/value stores for this app. Immutable, only valid when passed with --create.")
	methodAppCmd.Flags().Uint64Var(&localSchemaByteSlices, "local-byteslices", 0, "Maximum number of byte slices that may be stored in local (per-account) key/value stores for this app. Immutable, only valid when passed with --create.")
	methodAppCmd.Flags().Uint32Var(&extraPages, "extra-pages", 0, "Additional program space for supporting larger AVM bytecode program. A maximum of 3 extra pages is allowed. A page is 1024 bytes. Valid when passed with --create or when updating.")

	// Can't use PersistentFlags on the root because for some reason marking
	// a root command as required with MarkPersistentFlagRequired isn't
	// working
	callAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	optInAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	closeOutAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	clearAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	deleteAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	readStateAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	updateAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	infoAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	methodAppCmd.Flags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")

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

	panicIfErr(methodAppCmd.MarkFlagRequired("method"))
	panicIfErr(methodAppCmd.MarkFlagRequired("from"))
}

func panicIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

func newAppCallBytes(arg string) apps.AppCallBytes {
	appBytes, err := apps.NewAppCallBytes(arg)
	if err != nil {
		reportErrorln(err)
	}
	return appBytes
}

type appCallInputs struct {
	Accounts      []string            `codec:"accounts"`
	ForeignApps   []uint64            `codec:"foreignapps"`
	ForeignAssets []uint64            `codec:"foreignassets"`
	Boxes         []boxRef            `codec:"boxes"`
	Holdings      []holdingRef        `codec:"holdings"`
	Locals        []localRef          `codec:"locals"`
	UseAccess     bool                `codec:"access"`
	Args          []apps.AppCallBytes `codec:"args"`
}

type boxRef struct {
	appID uint64            `codec:"app"`
	name  apps.AppCallBytes `codec:"name"`
}

type holdingRef struct {
	assetID uint64 `codec:"asset"`
	address string `codec:"account"`
}

type localRef struct {
	appID   uint64 `codec:"app"`
	address string `codec:"account"`
}

// parseUInt64 parses a string into a uint64. It must succeed or the error is
// reprted and `goal` exits. It accepts extra arguments to create a more
// helpful error message.
func parseUInt64(number string, thing string, context ...string) uint64 {
	n, err := strconv.ParseUint(number, 10, 64)
	if err != nil {
		extra := ""
		if len(context) == 1 {
			extra = " in " + context[0]
		}
		reportErrorf("Could not parse '%s' as %s%s: %s",
			number, thing, extra, errors.Unwrap(err))
	}
	return n
}

// parseBoxRef parses a command-line box ref, which is an optional appId, a comma,
// and then the same format as an app call arg.
func parseBoxRef(arg string) boxRef {
	encoding, value, found := strings.Cut(arg, ":")
	if !found {
		reportErrorf("box refs should be of the form '[<app>,]encoding:value'")
	}
	appID := uint64(0)

	if appStr, enc, found := strings.Cut(encoding, ","); found {
		// There was a comma in the part before the ":"
		encoding = enc
		appID = parseUInt64(appStr, "app id", "box ref")
	}
	return boxRef{
		appID: appID,
		name:  newAppCallBytes(encoding + ":" + value),
	}
}

// parseHoldingRef parses a command-line box ref, which is an assetId and an
// optional address, separated by a plus sign. No address means Sender.
func parseHoldingRef(arg string) holdingRef {
	assetStr, address, _ := strings.Cut(arg, "+")
	assetID := parseUInt64(assetStr, "asset id", "holding ref")

	return holdingRef{
		assetID: assetID,
		address: address, // "" would mean Sender
	}
}

// parseLocalRef parses a command-line local state ref, which is an optional appId
// and an optional address, separated by a plus sign. No appId means the called app,
// No address means Sender. They can not _both_ be omitted, as that is a
// non-sensical LocalRef - it would make the local state of the sender for the
// current app available. That is implicitly available already.
func parseLocalRef(arg string) localRef {
	one, two, both := strings.Cut(arg, "+")

	if both {
		appID := parseUInt64(one, "app id", "local ref")
		return localRef{
			appID:   appID,
			address: two,
		}
	}

	// one is missing, so we should have a number or an address.  Try to parse
	// it as a number. If it fails, assume an address, because at this stage we
	// don't parse addresses.
	if appID, err := strconv.ParseUint(one, 10, 64); err == nil {
		return localRef{
			appID:   appID,
			address: "",
		}
	}

	return localRef{
		appID:   0,
		address: one,
	}
}

// parseAppInputs converts inputs from a very textual input form (coming from
// CLI or a JSON file), to a more strongly typed form, using the various "real"
// types from `basics`.
func parseAppInputs(inputs appCallInputs) ([][]byte, libgoal.RefBundle) {
	args := make([][]byte, 0, len(inputs.Args))
	for _, arg := range inputs.Args {
		rawValue, err := arg.Raw()
		if err != nil {
			reportErrorf("Could not decode app-arg %s:%s: %v", arg.Encoding, arg.Value, err)
		}
		args = append(args, rawValue)
	}
	locals := util.Map(inputs.Locals, func(hr localRef) basics.LocalRef {
		return basics.LocalRef{
			App:     basics.AppIndex(hr.appID),
			Address: cliAddress(hr.address)}
	})
	holdings := util.Map(inputs.Holdings, func(hr holdingRef) basics.HoldingRef {
		return basics.HoldingRef{
			Asset:   basics.AssetIndex(hr.assetID),
			Address: cliAddress(hr.address)}
	})
	boxes := util.Map(inputs.Boxes, func(br boxRef) basics.BoxRef {
		rawName, err := br.name.Raw()
		if err != nil {
			reportErrorf("Could not decode box name %s: %v", br.name, err)
		}
		return basics.BoxRef{App: basics.AppIndex(br.appID), Name: string(rawName)}
	})
	refs := libgoal.RefBundle{
		UseAccess: inputs.UseAccess,
		Accounts:  util.Map(inputs.Accounts, cliAddress),
		Apps:      util.Map(inputs.ForeignApps, func(idx uint64) basics.AppIndex { return basics.AppIndex(idx) }),
		Assets:    util.Map(inputs.ForeignAssets, func(idx uint64) basics.AssetIndex { return basics.AssetIndex(idx) }),

		Locals:   locals,
		Holdings: holdings,
		Boxes:    boxes,
	}
	return args, refs
}

func cliAddress(acct string) basics.Address {
	if acct == "" {
		return basics.Address{} // will be interpreted as Sender
	}
	if strings.HasPrefix(acct, "app(") && strings.HasSuffix(acct, ")") {
		appStr := acct[4 : len(acct)-1]
		appID := parseUInt64(appStr, "app id", acct)
		return basics.AppIndex(appID).Address()
	}
	addr, err := basics.UnmarshalChecksumAddress(acct)
	if err != nil {
		reportErrorln(err)
	}
	return addr
}

func getAppInputsFromFile() appCallInputs {
	reportWarnf("Using a JSON app input file is deprecated and will be removed soon. Please speak up if the feature matters to you.")
	time.Sleep(5 * time.Second)

	var inputs appCallInputs
	f, err := os.Open(appInputFilename)
	if err != nil {
		reportErrorf("Could not open app input JSON file: %v", err)
	}
	defer f.Close()

	dec := protocol.NewJSONDecoder(f)
	err = dec.Decode(&inputs)
	if err != nil {
		reportErrorf("Could not decode app input JSON file: %v", err)
	}

	return inputs
}

func getAppInputsFromCLI() appCallInputs {
	// we need to ignore empty strings from appArgs because app-arg was
	// previously a StringSliceVar, which also does that, and some test depend
	// on it. appArgs became `StringArrayVar` in order to support abi arguments
	// which contain commas.
	var encodedArgs []apps.AppCallBytes
	for _, arg := range appArgs {
		if len(arg) > 0 {
			encodedArgs = append(encodedArgs, newAppCallBytes(arg))
		}
	}

	return appCallInputs{
		UseAccess: appUseAccess,
		Accounts:  appStrAccounts,
		ForeignApps: util.Map(foreignApps, func(s string) uint64 {
			return parseUInt64(s, "app id", "foreign-app")
		}),
		ForeignAssets: util.Map(foreignAssets, func(s string) uint64 {
			return parseUInt64(s, "asset id", "foreign-asset")
		}),
		Boxes:    util.Map(appStrBoxes, parseBoxRef),
		Holdings: util.Map(appStrHoldings, parseHoldingRef),
		Locals:   util.Map(appStrLocals, parseLocalRef),
		Args:     encodedArgs,
	}
}

func getAppInputs() ([][]byte, libgoal.RefBundle) {
	var inputs appCallInputs
	if appInputFilename != "" {
		if appArgs != nil || appStrAccounts != nil ||
			foreignApps != nil || foreignAssets != nil || appStrBoxes != nil ||
			appStrHoldings != nil || appStrLocals != nil {
			reportErrorf("Cannot specify both command-line arguments/resources and JSON input filename")
		}
		inputs = getAppInputsFromFile()
	} else {
		inputs = getAppInputsFromCLI()
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
	dataDir = datadir.EnsureSingleDataDir()
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
		appArgs, refs := getAppInputs()

		switch onCompletionEnum {
		case transactions.CloseOutOC, transactions.ClearStateOC:
			reportWarnf("'--on-completion %s' may be ill-formed for 'goal app create'", onCompletion)
		}

		tx, err := client.MakeUnsignedAppCreateTx(onCompletionEnum, approvalProg, clearProg, globalSchema, localSchema,
			appArgs, refs, extraPages)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
			signedTxn, err2 := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, tx)
			if err2 != nil {
				reportErrorf(errorSigningTX, err2)
			}

			txid, err2 := client.BroadcastTransaction(signedTxn)
			if err2 != nil {
				reportErrorf(errorBroadcastingTX, err2)
			}

			reportInfof("Attempting to create app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), logic.HashProgram(clearProg))
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				txn, err1 := waitForCommit(client, txid, lv)
				if err1 != nil {
					reportErrorln(err1)
				}
				if txn.ApplicationIndex != nil && *txn.ApplicationIndex != 0 {
					reportInfof("Created app with app index %d", *txn.ApplicationIndex)
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
				reportErrorln(err)
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
		appArgs, refs := getAppInputs()

		tx, err := client.MakeUnsignedAppUpdateTx(appIdx, appArgs, approvalProg, clearProg, refs, rejectVersion)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}
		tx.GlobalStateSchema = basics.StateSchema{
			NumUint:      globalSchemaUints,
			NumByteSlice: globalSchemaByteSlices,
		}
		tx.ExtraProgramPages = extraPages

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
			signedTxn, err2 := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, tx)
			if err2 != nil {
				reportErrorf(errorSigningTX, err2)
			}

			txid, err2 := client.BroadcastTransaction(signedTxn)
			if err2 != nil {
				reportErrorf(errorBroadcastingTX, err2)
			}

			reportInfof("Attempting to update app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), logic.HashProgram(clearProg))
			reportInfof("Issued transaction from account %s, txid %s (fee %d)", tx.Sender, txid, tx.Fee.Raw)

			if !noWaitAfterSend {
				_, err2 = waitForCommit(client, txid, lv)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
			if err != nil {
				reportErrorln(err)
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
		appArgs, refs := getAppInputs()

		tx, err := client.MakeUnsignedAppOptInTx(appIdx, appArgs, refs, rejectVersion)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
				_, err2 = waitForCommit(client, txid, lv)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
			if err != nil {
				reportErrorln(err)
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
		appArgs, refs := getAppInputs()

		tx, err := client.MakeUnsignedAppCloseOutTx(appIdx, appArgs, refs, rejectVersion)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
				_, err2 = waitForCommit(client, txid, lv)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
			if err != nil {
				reportErrorln(err)
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
		appArgs, refs := getAppInputs()

		tx, err := client.MakeUnsignedAppClearStateTx(appIdx, appArgs, refs, rejectVersion)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
				_, err2 = waitForCommit(client, txid, lv)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
			if err != nil {
				reportErrorln(err)
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
		// Parse transaction parameters
		appArgs, refs := getAppInputs()
		dataDir, client := getDataDirAndClient()

		tx, err := client.MakeUnsignedAppNoOpTx(appIdx, appArgs, refs, rejectVersion)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
				_, err2 = waitForCommit(client, txid, lv)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
			if err != nil {
				reportErrorln(err)
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
		appArgs, refs := getAppInputs()

		tx, err := client.MakeUnsignedAppDeleteTx(appIdx, appArgs, refs, rejectVersion)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		tx.Note = parseNoteField(cmd)
		tx.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
				_, err2 = waitForCommit(client, txid, lv)
				if err2 != nil {
					reportErrorln(err2)
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, tx, outFilename)
			} else {
				err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			}
			if err != nil {
				reportErrorln(err)
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

		fmt.Printf("Application ID:        %d\n", appIdx)
		fmt.Printf("Application account:   %v\n", appIdx.Address())
		fmt.Printf("Creator:               %v\n", params.Creator)
		fmt.Printf("Approval hash:         %v\n", basics.Address(logic.HashProgram(params.ApprovalProgram)))
		fmt.Printf("Clear hash:            %v\n", basics.Address(logic.HashProgram(params.ClearStateProgram)))

		ver := params.Version
		if ver != nil {
			fmt.Printf("Program version:       %d\n", *ver)
		}

		sponsor := params.SizeSponsor
		if sponsor != nil {
			fmt.Printf("Size sponsor:        %v\n", *sponsor)
		}

		epp := params.ExtraProgramPages
		if epp != nil {
			fmt.Printf("Extra program pages:   %d\n", *epp)
		}

		gsch := params.GlobalStateSchema
		if gsch != nil {
			fmt.Printf("Max global byteslices: %d\n", gsch.NumByteSlice)
			fmt.Printf("Max global integers:   %d\n", gsch.NumUint)
		}

		lsch := params.LocalStateSchema
		if lsch != nil {
			fmt.Printf("Max local byteslices:  %d\n", lsch.NumByteSlice)
			fmt.Printf("Max local integers:    %d\n", lsch.NumUint)
		}
	},
}

// populateMethodCallTxnArgs parses and loads transactions from the files indicated by the values
// slice. An error will occur if the transaction does not match the expected type, it has a nonzero
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
func populateMethodCallReferenceArgs(sender string, currentApp basics.AppIndex, types []string, values []string, refs *libgoal.RefBundle) ([]int, error) {
	resolvedIndexes := make([]int, len(types))

	for i, value := range values {
		var resolved int

		switch types[i] {
		case abi.AccountReferenceType:
			if value == sender {
				resolved = 0
			} else {
				valAddress := cliAddress(value)
				duplicate := false
				for j, account := range refs.Accounts {
					if valAddress == account {
						resolved = j + 1 // + 1 because 0 is the sender
						duplicate = true
						break
					}
				}
				if !duplicate {
					resolved = len(refs.Accounts) + 1
					refs.Accounts = append(refs.Accounts, valAddress)
				}
			}
		case abi.ApplicationReferenceType:
			ui := parseUInt64(value, "app id")
			appID := basics.AppIndex(ui)
			if appID == currentApp {
				resolved = 0
			} else {
				duplicate := false
				for j, app := range refs.Apps {
					if appID == app {
						resolved = j + 1 // + 1 because 0 is the current app
						duplicate = true
						break
					}
				}
				if !duplicate {
					resolved = len(refs.Apps) + 1
					refs.Apps = append(refs.Apps, appID)
				}
			}
		case abi.AssetReferenceType:
			ui := parseUInt64(value, "asset id")
			assetID := basics.AssetIndex(ui)
			duplicate := false
			for j, asset := range refs.Assets {
				if assetID == asset {
					resolved = j
					duplicate = true
					break
				}
			}
			if !duplicate {
				resolved = len(refs.Assets)
				refs.Assets = append(refs.Assets, assetID)
			}
		default:
			return nil, fmt.Errorf("Unknown reference type: %s", types[i])
		}

		resolvedIndexes[i] = resolved
	}

	return resolvedIndexes, nil
}

// maxAppArgs is the maximum number of arguments for an application call transaction, in compliance
// with ARC-4. Currently this is the same as the MaxAppArgs consensus parameter, but the
// difference is that the consensus parameter is liable to change in a future consensus upgrade.
// However, the ARC-4 ABI argument encoding **MUST** always remain the same.
const maxAppArgs = 16

// The tuple threshold is maxAppArgs, minus 1 for the method selector in the first app arg,
// minus 1 for the final app argument becoming a tuple of the remaining method args
const methodArgsTupleThreshold = maxAppArgs - 2

// parseMethodArgJSONtoByteSlice convert input method arguments to ABI encoded bytes
// it converts funcArgTypes into a tuple type and apply changes over input argument string (in JSON format)
// if there are greater or equal to 15 inputs, then we compact the tailing inputs into one tuple
func parseMethodArgJSONtoByteSlice(argTypes []string, jsonArgs []string, applicationArgs *[][]byte) error {
	abiTypes := make([]abi.Type, len(argTypes))
	for i, typeString := range argTypes {
		abiType, err := abi.TypeOf(typeString)
		if err != nil {
			return err
		}
		abiTypes[i] = abiType
	}

	if len(abiTypes) != len(jsonArgs) {
		return fmt.Errorf("input argument number %d != method argument number %d", len(jsonArgs), len(abiTypes))
	}

	// Up to 16 app arguments can be passed to app call. First is reserved for method selector,
	// and the rest are for method call arguments. But if more than 15 method call arguments
	// are present, then the method arguments after the 14th are placed in a tuple in the last
	// app argument slot
	if len(abiTypes) > maxAppArgs-1 {
		typesForTuple := make([]abi.Type, len(abiTypes)-methodArgsTupleThreshold)
		copy(typesForTuple, abiTypes[methodArgsTupleThreshold:])

		compactedType, err := abi.MakeTupleType(typesForTuple)
		if err != nil {
			return err
		}

		abiTypes = append(abiTypes[:methodArgsTupleThreshold], compactedType)

		tupleValues := make([]json.RawMessage, len(jsonArgs)-methodArgsTupleThreshold)
		for i, jsonArg := range jsonArgs[methodArgsTupleThreshold:] {
			tupleValues[i] = []byte(jsonArg)
		}

		remainingJSON, err := json.Marshal(tupleValues)
		if err != nil {
			return err
		}

		jsonArgs = append(jsonArgs[:methodArgsTupleThreshold], string(remainingJSON))
	}

	// parse JSON value to ABI encoded bytes
	for i := 0; i < len(jsonArgs); i++ {
		interfaceVal, err := abiTypes[i].UnmarshalFromJSON([]byte(jsonArgs[i]))
		if err != nil {
			return err
		}
		abiEncoded, err := abiTypes[i].Encode(interfaceVal)
		if err != nil {
			return err
		}
		*applicationArgs = append(*applicationArgs, abiEncoded)
	}
	return nil
}

var methodAppCmd = &cobra.Command{
	Use:   "method",
	Short: "Invoke an ABI method",
	Long:  `Invoke an ARC-4 ABI method on an App (stateful contract) with an application call transaction`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir, client := getDataDirAndClient()

		// Parse transaction parameters
		appArgsParsed, refs := getAppInputs()
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

			if rejectVersion != 0 {
				reportErrorf("--reject-version should not be provided with --create")
			}
		} else {
			if appIdx == 0 {
				reportErrorf("one of --app-id or --create must be provided")
			}

			if onCompletionEnum != transactions.UpdateApplicationOC {
				if !globalSchema.Empty() {
					reportErrorf("--global-ints, --global-byteslices, --local-ints, and --local-byteslices must only be provided with --create or when updating")
				}
				if extraPages != 0 {
					reportErrorf("--extra-pages must only be provided with --create or when updating")
				}
			}
			if !localSchema.Empty() {
				reportErrorf("--local-ints and --local-byteslices must only be provided with --create")
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
			theRetType, typeErr := abi.TypeOf(retTypeStr)
			if typeErr != nil {
				reportErrorf("cannot cast %s to abi type: %v", retTypeStr, typeErr)
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

		refArgsResolved, err := populateMethodCallReferenceArgs(account, basics.AppIndex(appIdx), refArgTypes, refArgValues, &refs)
		if err != nil {
			reportErrorf("error populating reference arguments: %v", err)
		}
		for i, resolved := range refArgsResolved {
			basicArgIndex := refArgIndexToBasicArgIndex[i]
			// use the foreign array index as the encoded argument value
			basicArgValues[basicArgIndex] = strconv.Itoa(resolved)
		}

		err = parseMethodArgJSONtoByteSlice(basicArgTypes, basicArgValues, &applicationArgs)
		if err != nil {
			reportErrorf("cannot parse arguments to ABI encoding: %v", err)
		}

		txnArgs, err := populateMethodCallTxnArgs(txnArgTypes, txnArgValues)
		if err != nil {
			reportErrorf("error populating transaction arguments: %v", err)
		}

		appCallTxn, err := client.MakeUnsignedApplicationCallTx(
			appIdx, applicationArgs, refs,
			onCompletionEnum, approvalProg, clearProg, globalSchema, localSchema, extraPages, rejectVersion)

		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}

		// Fill in note and lease
		appCallTxn.Note = parseNoteField(cmd)
		appCallTxn.Lease = parseLease(cmd)

		// Fill in rounds, fee, etc.
		fv, lv, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
			groupID, gidErr := client.GroupID(txnGroup)
			if gidErr != nil {
				reportErrorf("Cannot assign transaction group ID: %s", gidErr)
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

			signedTxn, signErr := createSignedTransaction(client, shouldSign, dataDir, walletName, unsignedTxn, txnFromArgs.AuthAddr)
			if signErr != nil {
				reportErrorf(errorSigningTX, signErr)
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
				reportErrorln(err)
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
			reportInfof("Attempting to create app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), logic.HashProgram(clearProg))
		} else if onCompletionEnum == transactions.UpdateApplicationOC {
			reportInfof("Attempting to update app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), logic.HashProgram(clearProg))
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
				reportErrorln(err)
			}

			resp, err := client.PendingTransactionInformation(txid)
			if err != nil {
				reportErrorln(err)
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
