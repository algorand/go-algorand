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
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
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

type appInteractProc struct {
	Create       bool   `json:"create"`
	OnCompletion string `json:"on-completion"`
	Help         string `json:"help"`

	Args        []appInteractArg     `json:"args"`
	Accounts    []appInteractAccount `json:"accounts"`
	ForeignApps []appInteractForeign `json:"foreign"`
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
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Help   string `json:"help"`
	Pseudo bool   `json:"pseudo"`
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

type appInteractForeign struct {
	Name string `json:"name"`
	Help string `json:"help"`
}

// map key -> data
type appInteractSchema map[string]appInteractSchemaEntry

type appInteractSchemaEntry struct {
	Key      string `json:"key"`
	Kind     string `json:"kind"`
	Help     string `json:"help"`
	Explicit bool   `json:"explicit"`
}

func (entry appInteractSchemaEntry) kind() string {
	return entry.Kind
}

func (entry appInteractSchemaEntry) help() string {
	return entry.Help
}

func (entry appInteractSchemaEntry) pseudo() bool {
	return false
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
	for _, arg := range sch {
		switch arg.Kind {
		case "int", "integer":
			schema.NumUint += 1
		default:
			schema.NumByteSlice += 1
		}
	}
	return
}

type appInteractState struct {
	Global appInteractSchema `json:"global"`
	Local  appInteractSchema `json:"local"`
}

type appInteractHeader struct {
	// map procedure name -> procedure
	Execute map[string]appInteractProc `json:"execute"`

	Query appInteractState `json:"query"`
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
					reportErrorf("Could not unmarshal address %s", addr)
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

		var approvalProg, clearProg []byte
		var tx transactions.Transaction
		var err error
		if appIdx == 0 {
			approvalProg, clearProg = mustParseProgArgs()
			localSchema := header.Query.Local.ToStateSchema()
			globalSchema := header.Query.Global.ToStateSchema()
			tx, err = client.MakeUnsignedAppCreateTx(onCompletion, approvalProg, clearProg, globalSchema, localSchema, appArgs, appAccounts, foreignApps)
		} else {
			switch onCompletion {
			case transactions.NoOpOC:
				tx, err = client.MakeUnsignedAppNoOpTx(appIdx, appArgs, appAccounts, foreignApps)
			case transactions.OptInOC:
				tx, err = client.MakeUnsignedAppOptInTx(appIdx, appArgs, appAccounts, foreignApps)
			case transactions.CloseOutOC:
				tx, err = client.MakeUnsignedAppCloseOutTx(appIdx, appArgs, appAccounts, foreignApps)
			case transactions.ClearStateOC:
				tx, err = client.MakeUnsignedAppClearStateTx(appIdx, appArgs, appAccounts, foreignApps)
			case transactions.UpdateApplicationOC:
				approvalProg, clearProg = mustParseProgArgs()
				tx, err = client.MakeUnsignedAppUpdateTx(appIdx, appArgs, appAccounts, foreignApps, approvalProg, clearProg)
			case transactions.DeleteApplicationOC:
				tx, err = client.MakeUnsignedAppDeleteTx(appIdx, appArgs, appAccounts, foreignApps)
			default:
				reportErrorf("Unknown onCompletion value %s", onCompletion)
			}
		}
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

			if appIdx == 0 {
				reportInfof("Attempting to create app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), crypto.HashObj(logic.Program(clearProg)))
			} else if onCompletion == transactions.UpdateApplicationOC {
				reportInfof("Attempting to update app (approval size %d, hash %v; clear size %d, hash %v)", len(approvalProg), crypto.HashObj(logic.Program(approvalProg)), len(clearProg), crypto.HashObj(logic.Program(clearProg)))
			}
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
			// Broadcast or write transaction to file
			err = writeTxnToFile(client, sign, dataDir, walletName, tx, txFilename)
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

		enckey := base64.StdEncoding.EncodeToString([]byte(meta.Key))
		var tealval v1.TealValue
		if scope == "local" {
			// Fetching local state. Get account information
			response, err := client.AccountInformation(account)
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			// Get application local state
			local, ok := response.AppLocalStates[appIdx]
			if !ok {
				reportErrorf(errorAccountNotOptedInToApp, account, appIdx)
			}

			kv := local.KeyValue
			tealval = kv[enckey]
		}

		if scope == "global" {
			// Fetching global state. Get application information
			params, err := client.ApplicationInformation(appIdx)
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			kv := params.GlobalState
			tealval = kv[enckey]
		}

		var decoded string
		switch meta.Kind {
		case "int", "integer":
			if tealval.Type == "" {
				if meta.Explicit {
					reportErrorf("%s not set for %s.%s", param, appIdx, storeName)
				}
			} else if tealval.Type != "u" {
				reportErrorf("Expected kind %s but got teal type %s", meta.Kind, tealval.Type)
			}
			decoded = fmt.Sprintf("%d", tealval.Uint)
		default:
			if tealval.Type == "" {
				if meta.Explicit {
					reportErrorf("%s not set for %s.%s", param, appIdx, storeName)
				}
			} else if tealval.Type != "b" {
				reportErrorf("Expected kind %s but got teal type %s", meta.Kind, tealval.Type)
			}
			raw, err := base64.StdEncoding.DecodeString(tealval.Bytes)
			if err != nil {
				reportErrorf("Fatal error: could not decode base64-encoded string: %s", tealval.Bytes)
			}
			switch meta.Kind {
			case "str", "string":
				decoded = string(raw)
			case "addr", "address":
				var addr basics.Address
				copy(addr[:], raw)
				decoded = addr.String()
			case "b32", "base32", "byte base32":
				decoded = base32.StdEncoding.EncodeToString(raw)
			case "b64", "base64", "byte base64":
				fallthrough
			default:
				decoded = string(tealval.Bytes)
			}
		}
		reportInfoln(decoded)
	},
}
