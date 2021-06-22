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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

var (
	appHdr string
)

func init() {
	appCmd.AddCommand(appInteractCmd)

	appInteractCmd.AddCommand(appExecuteCmd)
	appInteractCmd.AddCommand(appQueryCmd)
	appInteractCmd.PersistentFlags().StringVarP(&appHdr, "header", "", "", "Application header")

	appQueryCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	appQueryCmd.Flags().StringVarP(&account, "from", "f", "", "Account to query state for (if omitted, query from global state)")
	appQueryCmd.Flags().SetInterspersed(false)
	appQueryCmd.MarkFlagRequired("app-id")

	appExecuteCmd.Flags().Uint64Var(&appIdx, "app-id", 0, "Application ID (if omitted, zero, which creates an application)")
	appExecuteCmd.Flags().StringVarP(&account, "from", "f", "", "Account to execute interaction from")
	appExecuteCmd.Flags().SetInterspersed(false)
	appExecuteCmd.MarkFlagRequired("from")
}

var appInteractCmd = &cobra.Command{
	Use:   "interact",
	Short: "Interact with an application",
	Args:  cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

type appInteractDatum interface {
	kind() string
	help() string
	pseudo() bool
}

func helpList(help map[string]appInteractDatum) string {
	var names []string
	largestName := 0
	largestKind := 0
	for k, v := range help {
		if v.pseudo() {
			continue
		}
		if len(k) > largestName {
			largestName = len(k)
		}
		if len(v.kind()) > largestKind {
			largestKind = len(v.kind())
		}
		names = append(names, k)
	}

	namesize := "%-" + fmt.Sprintf("%d", largestName+3) + "s"
	kindsize := "%-" + fmt.Sprintf("%d", largestKind+3) + "s"
	fmtstr := "    " + namesize + " " + kindsize + " " + "%s"

	var entries []string
	for k, v := range help {
		if v.pseudo() {
			continue
		}
		entries = append(entries, fmt.Sprintf(fmtstr, k, v.kind(), v.help()))
	}
	return strings.Join(entries, "\n")
}

func appSpecRuneInvalid(r rune) bool {
	if 'a' <= r && r <= 'z' {
		return false
	}
	if 'A' <= r && r <= 'Z' {
		return false
	}
	if '0' <= r && r <= '9' {
		return false
	}
	if r == '-' || r == '+' || r == '_' {
		return false
	}
	return true
}

func appSpecStringInvalid(s string) error {
	for _, r := range s {
		if appSpecRuneInvalid(r) {
			return fmt.Errorf("%s contains an invalid rune", strconv.Quote(s))
		}
	}
	return nil
}

func appSpecHelpStringInvalid(s string) error {
	if printable, _ := unicodePrintable(s); !printable {
		return fmt.Errorf("%s is not Unicode printable", strconv.Quote(s))
	}
	return nil
}

type appInteractProc struct {
	Create       bool   `json:"create"`
	OnCompletion string `json:"on-completion"`
	Help         string `json:"help"`

	Args        []appInteractArg     `json:"args"`
	Accounts    []appInteractAccount `json:"accounts"`
	ForeignApps []appInteractForeign `json:"foreign"`
}

func (proc appInteractProc) validate() (err error) {
	err = appSpecStringInvalid(proc.OnCompletion)
	if err != nil {
		return fmt.Errorf("OnCompletion: %v", err)
	}
	err = appSpecHelpStringInvalid(proc.Help)
	if err != nil {
		return fmt.Errorf("Help: %v", err)
	}
	for i, arg := range proc.Args {
		err = arg.validate()
		if err != nil {
			return fmt.Errorf("Arg(%d): %v", i, err)
		}
	}
	for i, acc := range proc.Accounts {
		err = acc.validate()
		if err != nil {
			return fmt.Errorf("Account(%d): %v", i, err)
		}
	}
	for i, app := range proc.ForeignApps {
		err = app.validate()
		if err != nil {
			return fmt.Errorf("App(%d): %v", i, err)
		}
	}
	return
}

func (proc appInteractProc) kind() string {
	return proc.OnCompletion
}

func (proc appInteractProc) help() string {
	return proc.Help
}

func (proc appInteractProc) pseudo() bool {
	return false
}

type appInteractArg struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Help    string `json:"help"`
	Pseudo  bool   `json:"pseudo"`
	Default string `json:"default"`
}

func (arg appInteractArg) validate() (err error) {
	err = appSpecStringInvalid(arg.Name)
	if err != nil {
		return fmt.Errorf("Key: %v", err)
	}
	err = appSpecStringInvalid(arg.Kind)
	if err != nil {
		return fmt.Errorf("Kind: %v", err)
	}
	err = appSpecHelpStringInvalid(arg.Help)
	if err != nil {
		return fmt.Errorf("Help: %v", err)
	}
	// default values can be arbitrary
	// make sure to escape them before printing!
	// err = appSpecStringInvalid(arg.Default)
	return
}

func (arg appInteractArg) kind() string {
	return arg.Kind
}

func (arg appInteractArg) help() string {
	return arg.Help
}

func (arg appInteractArg) pseudo() bool {
	return arg.Pseudo
}

type appInteractAccount struct {
	Name     string `json:"name"`
	Help     string `json:"help"`
	Pseudo   bool   `json:"pseudo"` // TODO use this field in help
	Explicit bool   `json:"explicit"`
}

func (acc appInteractAccount) validate() (err error) {
	err = appSpecStringInvalid(acc.Name)
	if err != nil {
		return fmt.Errorf("Name: %v", err)
	}
	err = appSpecHelpStringInvalid(acc.Help)
	if err != nil {
		return fmt.Errorf("Help: %v", err)
	}
	return
}

type appInteractForeign struct {
	Name string `json:"name"`
	Help string `json:"help"`
}

func (f appInteractForeign) validate() (err error) {
	err = appSpecStringInvalid(f.Name)
	if err != nil {
		return fmt.Errorf("Name: %v", err)
	}
	err = appSpecHelpStringInvalid(f.Help)
	if err != nil {
		return fmt.Errorf("Help: %v", err)
	}
	return
}

// map key -> data
type appInteractSchema map[string]appInteractSchemaEntry

func (sch appInteractSchema) validate() (err error) {
	for k, v := range sch {
		err = appSpecStringInvalid(k)
		if err != nil {
			return fmt.Errorf("Key: %v", err)
		}
		err = v.validate()
		if err != nil {
			return fmt.Errorf("Entry(%s): %v", k, err)
		}
	}
	return
}

func (sch appInteractSchema) EntryList() string {
	help := make(map[string]appInteractDatum)
	for k, v := range sch {
		help[k] = v
	}
	return helpList(help)
}

func (sch appInteractSchema) EntryNames() (names []string) {
	for k := range sch {
		names = append(names, k)
	}
	return
}

func (sch appInteractSchema) ToStateSchema() (schema basics.StateSchema) {
	for name, entry := range sch {
		size := uint64(1)
		if entry.Map.Kind != "" {
			if entry.Size < 0 {
				reportErrorf("entry %s size %d < 0", name, entry.Size)
			}
			size = uint64(entry.Size)
		}
		switch entry.Kind {
		case "int", "integer":
			schema.NumUint += size
		default:
			schema.NumByteSlice += size
		}
	}
	return
}

type appInteractSchemaEntry struct {
	Key      string `json:"key"`
	Kind     string `json:"kind"`
	Help     string `json:"help"`
	Size     int    `json:"size"`
	Explicit bool   `json:"explicit"`

	Map appInteractMap `json:"map"` // TODO support for queries
}

func (entry appInteractSchemaEntry) validate() (err error) {
	err = appSpecStringInvalid(entry.Key)
	if err != nil {
		return fmt.Errorf("Key: %v", err)
	}
	err = appSpecStringInvalid(entry.Kind)
	if err != nil {
		return fmt.Errorf("Kind: %v", err)
	}
	err = appSpecHelpStringInvalid(entry.Help)
	if err != nil {
		return fmt.Errorf("Help: %v", err)
	}
	err = entry.Map.validate()
	if err != nil {
		return fmt.Errorf("Map: %v", err)
	}
	return
}

func (entry appInteractSchemaEntry) kind() string {
	if entry.Map.Kind != "" {
		return fmt.Sprintf("map %s -> %s", entry.Kind, entry.Map.Kind)
	}
	return entry.Kind
}

func (entry appInteractSchemaEntry) help() string {
	return entry.Help
}

func (entry appInteractSchemaEntry) pseudo() bool {
	return false
}

type appInteractMap struct {
	Kind   string `json:"kind"`
	Prefix string `json:"prefix"`
}

func (m appInteractMap) validate() (err error) {
	err = appSpecStringInvalid(m.Kind)
	if err != nil {
		return fmt.Errorf("Kind: %v", m.Kind)
	}
	err = appSpecStringInvalid(m.Prefix)
	if err != nil {
		return fmt.Errorf("Prefix: %v", m.Prefix)
	}
	return
}

type appInteractState struct {
	Global appInteractSchema `json:"global"`
	Local  appInteractSchema `json:"local"`
}

func (s appInteractState) validate() (err error) {
	err = s.Global.validate()
	if err != nil {
		return fmt.Errorf("Global: %v", err)
	}
	err = s.Local.validate()
	if err != nil {
		return fmt.Errorf("Local: %v", err)
	}
	return
}

// map procedure name -> procedure
type appInteractProcs map[string]appInteractProc

func (m appInteractProcs) validate() (err error) {
	for k, v := range m {
		err = appSpecStringInvalid(k)
		if err != nil {
			return fmt.Errorf("Key: %v", err)
		}
		err = v.validate()
		if err != nil {
			return fmt.Errorf("Proc(%s): %v", strconv.QuoteToASCII(k), err)
		}
	}
	return
}

type appInteractHeader struct {
	Execute appInteractProcs `json:"execute"`
	Query   appInteractState `json:"query"`
}

// TODO use reflect to recursively validate
func (hdr appInteractHeader) validate() (err error) {
	err = hdr.Execute.validate()
	if err != nil {
		return fmt.Errorf("Execute: %v", err)
	}
	err = hdr.Query.validate()
	if err != nil {
		return fmt.Errorf("Query: %v", err)
	}
	return
}

func (hdr appInteractHeader) ProcList() string {
	help := make(map[string]appInteractDatum)
	for k, v := range hdr.Execute {
		help[k] = v
	}
	return helpList(help)
}

func (hdr appInteractHeader) ProcNames() (names []string) {
	for k := range hdr.Execute {
		names = append(names, k)
	}
	return
}

func parseAppHeader() (header appInteractHeader) {
	if appHdr == "" {
		reportErrorf("No header file provided")
	}

	f, err := os.Open(appHdr)
	if err != nil {
		reportErrorf("Could not open app header file %s: %v", appHdr, err)
	}

	dec := json.NewDecoder(f)
	err = dec.Decode(&header)
	if err != nil {
		reportErrorf("Could not decode app header JSON file %s: %v", appHdr, err)
	}

	err = header.validate()
	if err != nil {
		reportErrorf("App header JSON file could not validate: %v", err)
	}

	return
}

// TODO print help correctly when --help is passed but procedure/state name is given
// TODO complain when unknown flags are given

var appExecuteCmd = &cobra.Command{
	Use:   "execute",
	Short: "Execute a procedure on an application",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		header := parseAppHeader()
		proc, ok := header.Execute[args[0]]
		if !ok {
			reportErrorf("Unknown procedure name %s.\nDefined procedures in %s:\n%s", args[0], appHdr, header.ProcList())
		}

		if proc.Create != (appIdx == 0) {
			reportErrorf("Procedure %s has the create flag set to %v, but application ID set to %d", args[0], proc.Create, appIdx)
		}

		procFlags := cmd.Flags()
		procFlags.SetInterspersed(true)
		procArgs := make(map[string]interface{})
		procAccounts := make(map[string]*string)
		procApps := make(map[string]*uint64)
		for _, arg := range proc.Args {
			switch arg.Kind {
			case "int", "integer":
				procArgs[arg.Name] = procFlags.Uint64(arg.Name, 0, arg.Help)
			default:
				procArgs[arg.Name] = procFlags.String(arg.Name, "", arg.Help)
			}
		}
		for _, account := range proc.Accounts {
			procAccounts[account.Name] = procFlags.String(account.Name, "", account.Help)
		}
		for _, app := range proc.ForeignApps {
			procApps[app.Name] = procFlags.Uint64(app.Name, 0, app.Help)
		}
		procFlags.Parse(os.Args[1:])

		var inputs appCallInputs
		for _, arg := range proc.Args {
			var callArg appCallArg
			callArg.Encoding = arg.Kind

			if !procFlags.Changed(arg.Name) && arg.Default != "" {
				callArg.Value = arg.Default
			} else {
				v := procArgs[arg.Name]
				s, ok := v.(*string)
				if ok {
					callArg.Value = *s
				} else {
					i, ok := v.(*uint64)
					if ok {
						// TODO this decodes and re-encodes redundantly
						callArg.Value = strconv.FormatUint(*i, 10)
					} else {
						reportErrorf("Could not re-encode key %s", arg.Name)
					}
				}
			}
			inputs.Args = append(inputs.Args, callArg)
		}
		for _, account := range proc.Accounts {
			var addr basics.Address
			s := *procAccounts[account.Name]
			if s == "" {
				if account.Explicit {
					reportErrorf("Required account %s not provided", account.Name)
				}
			} else {
				var err error
				addr, err = basics.UnmarshalChecksumAddress(s)
				if err != nil {
					reportErrorf("Could not unmarshal address for %s (%s): %v", account.Name, s, err)
				}
			}
			inputs.Accounts = append(inputs.Accounts, addr.String())
		}
		for _, app := range proc.ForeignApps {
			inputs.ForeignApps = append(inputs.ForeignApps, *procApps[app.Name])
		}

		if proc.OnCompletion == "" {
			proc.OnCompletion = "NoOp"
		}
		onCompletion := mustParseOnCompletion(proc.OnCompletion)
		appAccounts := inputs.Accounts
		foreignApps := inputs.ForeignApps
		foreignAssets := inputs.ForeignAssets

		appArgs := make([][]byte, len(inputs.Args))
		for i, arg := range inputs.Args {
			rawValue, err := parseAppArg(arg)
			if err != nil {
				reportErrorf("Could not parse argument corresponding to '%s': %v", proc.Args[i].Name, err)
			}
			appArgs[i] = rawValue
		}

		if appIdx == 0 {
			switch onCompletion {
			case transactions.CloseOutOC, transactions.ClearStateOC:
				reportWarnf("OnCompletion %s may be ill-formed when creating an application", onCompletion)
			}
		}

		var localSchema, globalSchema basics.StateSchema
		var approvalProg, clearProg []byte
		if appIdx == 0 {
			approvalProg, clearProg = mustParseProgArgs()
			localSchema = header.Query.Local.ToStateSchema()
			globalSchema = header.Query.Global.ToStateSchema()
		}
		tx, err := client.MakeUnsignedApplicationCallTx(appIdx, appArgs, appAccounts, foreignApps, foreignAssets, onCompletion, approvalProg, clearProg, globalSchema, localSchema, 0)
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

			if appIdx == 0 {
				reportInfof("Attempting to create app (global ints %d, global blobs %d, local ints %d, local blobs %d, approval size %d, hash %v; clear size %d, hash %v)", globalSchema.NumUint, globalSchema.NumByteSlice, localSchema.NumUint, localSchema.NumByteSlice, len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), crypto.HashObj(logic.Program(clearProg)))
			} else if onCompletion == transactions.UpdateApplicationOC {
				reportInfof("Attempting to update app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), crypto.HashObj(logic.Program(clearProg)))
			}
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
			// Broadcast or write transaction to file
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, outFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var appQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query local or global state from an application",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		header := parseAppHeader()
		scope := "local"
		storeName := account
		lookup := header.Query.Local
		if account == "" {
			scope = "global"
			storeName = "<global>"
			lookup = header.Query.Global
		}

		param := args[0]
		meta, ok := lookup[param]
		if !ok {
			reportErrorf("Unknown schema entry %s.\nDefined %s schema entries in %s:\n%s", param, scope, appHdr, lookup.EntryList())
		}

		var tealval basics.TealValue
		if scope == "local" {
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
			tealval = kv[meta.Key]
		}

		if scope == "global" {
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
			tealval = kv[meta.Key]
		}

		var decoded string
		switch meta.Kind {
		case "int", "integer":
			if tealval.Type == 0 {
				if meta.Explicit {
					reportErrorf("%s not set for %d.%s", param, appIdx, storeName)
				}
			} else if tealval.Type != basics.TealUintType {
				reportErrorf("Expected kind %s but got teal type %s", meta.Kind, tealval.Type)
			}
			decoded = fmt.Sprintf("%d", tealval.Uint)
		default:
			if tealval.Type == 0 {
				if meta.Explicit {
					reportErrorf("%s not set for %d.%s", param, appIdx, storeName)
				}
			} else if tealval.Type != basics.TealBytesType {
				reportErrorf("Expected kind %s but got teal type %s", meta.Kind, tealval.Type)
			}
			raw := []byte(tealval.Bytes)
			switch meta.Kind {
			case "str", "string":
				decoded = tealval.Bytes
			case "addr", "address":
				var addr basics.Address
				copy(addr[:], raw)
				decoded = addr.String()
			case "b32", "base32", "byte base32":
				decoded = base32.StdEncoding.EncodeToString(raw)
			case "b64", "base64", "byte base64":
				decoded = base64.StdEncoding.EncodeToString(raw)
			default:
				decoded = tealval.Bytes
			}
		}
		reportInfoln(decoded)
	},
}
