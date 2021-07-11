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
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	algodAcct "github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/db"
)

var (
	accountAddress     string
	walletName         string
	defaultAccountName string
	defaultAccount     bool
	unencryptedWallet  bool
	online             bool
	accountName        string
	transactionFee     uint64
	statusChangeLease  string
	statusChangeTxFile string
	roundFirstValid    uint64
	roundLastValid     uint64
	keyDilution        uint64
	threshold          uint8
	partKeyOutDir      string
	partKeyFile        string
	partKeyDeleteInput bool
	importDefault      bool
	mnemonic           string
	dumpOutFile        string
	listAccountInfo    bool
)

func init() {
	accountCmd.AddCommand(newCmd)
	accountCmd.AddCommand(deleteCmd)
	accountCmd.AddCommand(listCmd)
	accountCmd.AddCommand(renameCmd)
	accountCmd.AddCommand(infoCmd)
	accountCmd.AddCommand(balanceCmd)
	accountCmd.AddCommand(rewardsCmd)
	accountCmd.AddCommand(changeOnlineCmd)
	accountCmd.AddCommand(addParticipationKeyCmd)
	accountCmd.AddCommand(installParticipationKeyCmd)
	accountCmd.AddCommand(listParticipationKeysCmd)
	accountCmd.AddCommand(importCmd)
	accountCmd.AddCommand(exportCmd)
	accountCmd.AddCommand(importRootKeysCmd)
	accountCmd.AddCommand(accountMultisigCmd)
	accountCmd.AddCommand(markNonparticipatingCmd)

	accountMultisigCmd.AddCommand(newMultisigCmd)
	accountMultisigCmd.AddCommand(deleteMultisigCmd)
	accountMultisigCmd.AddCommand(infoMultisigCmd)

	accountCmd.AddCommand(renewParticipationKeyCmd)
	accountCmd.AddCommand(renewAllParticipationKeyCmd)

	accountCmd.AddCommand(partkeyInfoCmd)

	accountCmd.AddCommand(dumpCmd)

	// Wallet to be used for the account operation
	accountCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")

	// Account Flag
	accountCmd.Flags().StringVarP(&defaultAccountName, "default", "f", "", "Set the account with this name to be the default account")

	// New Account flag
	newCmd.Flags().BoolVarP(&defaultAccount, "default", "f", false, "Set this account as the default one")

	// Delete account flag
	deleteCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Address of account to delete")
	deleteCmd.MarkFlagRequired("address")

	// New Multisig account flag
	newMultisigCmd.Flags().Uint8VarP(&threshold, "threshold", "T", 1, "Number of signatures required to spend from this address")
	newMultisigCmd.MarkFlagRequired("threshold")

	// Delete multisig account flag
	deleteMultisigCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Address of multisig account to delete")
	deleteMultisigCmd.MarkFlagRequired("address")

	// Lookup info for multisig account flag
	infoMultisigCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Address of multisig account to look up")
	infoMultisigCmd.MarkFlagRequired("address")

	// Account list flags
	listCmd.Flags().BoolVar(&listAccountInfo, "info", false, "Include additional information about each account's assets and applications")

	// Info flags
	infoCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to look up (required)")
	infoCmd.MarkFlagRequired("address")

	// Balance flags
	balanceCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to retrieve balance (required)")
	balanceCmd.MarkFlagRequired("address")

	// Rewards flags
	rewardsCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to retrieve rewards (required)")
	rewardsCmd.MarkFlagRequired("address")

	// changeOnlineStatus flags
	changeOnlineCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to change (required if no -partkeyfile)")
	changeOnlineCmd.Flags().StringVarP(&partKeyFile, "partkeyfile", "", "", "Participation key file (required if no -account)")
	changeOnlineCmd.Flags().BoolVarP(&online, "online", "o", true, "Set this account to online or offline")
	changeOnlineCmd.Flags().Uint64VarP(&transactionFee, "fee", "f", 0, "The Fee to set on the status change transaction (defaults to suggested fee)")
	changeOnlineCmd.Flags().Uint64VarP(&firstValid, "firstRound", "", 0, "")
	changeOnlineCmd.Flags().Uint64VarP(&firstValid, "firstvalid", "", 0, "FirstValid for the status change transaction (0 for current)")
	changeOnlineCmd.Flags().Uint64VarP(&numValidRounds, "validRounds", "", 0, "")
	changeOnlineCmd.Flags().Uint64VarP(&numValidRounds, "validrounds", "v", 0, "The validity period for the status change transaction")
	changeOnlineCmd.Flags().Uint64Var(&lastValid, "lastvalid", 0, "The last round where the transaction may be committed to the ledger")
	changeOnlineCmd.Flags().StringVarP(&statusChangeLease, "lease", "x", "", "Lease value (base64, optional): no transaction may also acquire this lease until lastvalid")
	changeOnlineCmd.Flags().StringVarP(&statusChangeTxFile, "txfile", "t", "", "Write status change transaction to this file")
	changeOnlineCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	changeOnlineCmd.Flags().MarkDeprecated("firstRound", "use --firstvalid instead")
	changeOnlineCmd.Flags().MarkDeprecated("validRounds", "use --validrounds instead")

	// addParticipationKey flags
	addParticipationKeyCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account to associate with the generated partkey")
	addParticipationKeyCmd.MarkFlagRequired("address")
	addParticipationKeyCmd.Flags().Uint64VarP(&roundFirstValid, "roundFirstValid", "", 0, "The first round for which the generated partkey will be valid")
	addParticipationKeyCmd.MarkFlagRequired("roundFirstValid")
	addParticipationKeyCmd.Flags().Uint64VarP(&roundLastValid, "roundLastValid", "", 0, "The last round for which the generated partkey will be valid")
	addParticipationKeyCmd.MarkFlagRequired("roundLastValid")
	addParticipationKeyCmd.Flags().StringVarP(&partKeyOutDir, "outdir", "o", "", "Save participation key file to specified output directory to (for offline creation)")
	addParticipationKeyCmd.Flags().Uint64VarP(&keyDilution, "keyDilution", "", 0, "Key dilution for two-level participation keys")

	// installParticipationKey flags
	installParticipationKeyCmd.Flags().StringVar(&partKeyFile, "partkey", "", "Participation key file to install")
	installParticipationKeyCmd.MarkFlagRequired("partkey")
	installParticipationKeyCmd.Flags().BoolVar(&partKeyDeleteInput, "delete-input", false, "Acknowledge that installpartkey will delete the input key file")

	// import flags
	importCmd.Flags().BoolVarP(&importDefault, "default", "f", false, "Set this account as the default one")
	importCmd.Flags().StringVarP(&mnemonic, "mnemonic", "m", "", "Mnemonic to import (will prompt otherwise)")
	// export flags
	exportCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Address of account to export")
	exportCmd.MarkFlagRequired("address")
	// importRootKeys flags
	importRootKeysCmd.Flags().BoolVarP(&unencryptedWallet, "unencrypted-wallet", "u", false, "Import into the default unencrypted wallet, potentially creating it")

	// renewParticipationKeyCmd
	renewParticipationKeyCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to update (required)")
	renewParticipationKeyCmd.MarkFlagRequired("address")
	renewParticipationKeyCmd.Flags().Uint64VarP(&transactionFee, "fee", "f", 0, "The Fee to set on the status change transaction (defaults to suggested fee)")
	renewParticipationKeyCmd.Flags().Uint64VarP(&roundLastValid, "roundLastValid", "", 0, "The last round for which the generated partkey will be valid")
	renewParticipationKeyCmd.MarkFlagRequired("roundLastValid")
	renewParticipationKeyCmd.Flags().Uint64VarP(&keyDilution, "keyDilution", "", 0, "Key dilution for two-level participation keys")
	renewParticipationKeyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")

	// renewAllParticipationKeyCmd
	renewAllParticipationKeyCmd.Flags().Uint64VarP(&transactionFee, "fee", "f", 0, "The Fee to set on the status change transactions (defaults to suggested fee)")
	renewAllParticipationKeyCmd.Flags().Uint64VarP(&roundLastValid, "roundLastValid", "", 0, "The last round for which the generated partkeys will be valid")
	renewAllParticipationKeyCmd.MarkFlagRequired("roundLastValid")
	renewAllParticipationKeyCmd.Flags().Uint64VarP(&keyDilution, "keyDilution", "", 0, "Key dilution for two-level participation keys")
	renewAllParticipationKeyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")

	// markNonparticipatingCmd flags
	markNonparticipatingCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to change")
	markNonparticipatingCmd.MarkFlagRequired("address")
	markNonparticipatingCmd.Flags().Uint64VarP(&transactionFee, "fee", "f", 0, "The Fee to set on the status change transaction (defaults to suggested fee)")
	markNonparticipatingCmd.Flags().Uint64VarP(&firstValid, "firstRound", "", 0, "")
	markNonparticipatingCmd.Flags().Uint64VarP(&firstValid, "firstvalid", "", 0, "FirstValid for the status change transaction (0 for current)")
	markNonparticipatingCmd.Flags().Uint64VarP(&numValidRounds, "validRounds", "", 0, "")
	markNonparticipatingCmd.Flags().Uint64VarP(&numValidRounds, "validrounds", "v", 0, "The validity period for the status change transaction")
	markNonparticipatingCmd.Flags().Uint64Var(&lastValid, "lastvalid", 0, "The last round where the transaction may be committed to the ledger")
	markNonparticipatingCmd.Flags().StringVarP(&statusChangeTxFile, "txfile", "t", "", "Write status change transaction to this file, rather than posting to network")
	markNonparticipatingCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	markNonparticipatingCmd.Flags().MarkDeprecated("firstRound", "use --firstvalid instead")
	markNonparticipatingCmd.Flags().MarkDeprecated("validRounds", "use --validrounds instead")

	dumpCmd.Flags().StringVarP(&dumpOutFile, "outfile", "o", "", "Save balance record to specified output file")
	dumpCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to retrieve balance (required)")
	balanceCmd.MarkFlagRequired("address")
}

func scLeaseBytes(cmd *cobra.Command) (leaseBytes [32]byte) {
	if cmd.Flags().Changed("lease") {
		leaseBytesRaw, err := base64.StdEncoding.DecodeString(statusChangeLease)
		if err != nil {
			reportErrorf(malformedLease, lease, err)
		}
		if len(leaseBytesRaw) != 32 {
			reportErrorf(malformedLease, lease, fmt.Errorf("lease length %d != 32", len(leaseBytesRaw)))
		}
		copy(leaseBytes[:], leaseBytesRaw)
	}
	return
}

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Control and manage Algorand accounts",
	Long:  `Collection of commands to support the creation and management of accounts / wallets tied to a specific Algorand node instance.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		accountList := makeAccountsList(ensureSingleDataDir())

		// Update the default account
		if defaultAccountName != "" {
			// If the name doesn't exist, return an error
			if !accountList.isTaken(defaultAccountName) {
				reportErrorf(errorNameDoesntExist, defaultAccountName)
			}
			// Set the account with this name to be default
			accountList.setDefault(defaultAccountName)
			reportInfof(infoSetAccountToDefault, defaultAccountName)
			os.Exit(0)
		}

		// Return the help text
		cmd.HelpFunc()(cmd, args)
	},
}

var accountMultisigCmd = &cobra.Command{
	Use:   "multisig",
	Short: "Control and manage multisig accounts",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// Return the help text
		cmd.HelpFunc()(cmd, args)
	},
}

var renameCmd = &cobra.Command{
	Use:   "rename [old name] [new name]",
	Short: "Change the human-friendly name of an account",
	Long:  `Change the human-friendly name of an account. This is a local-only name, it is not stored on the network.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		accountList := makeAccountsList(ensureSingleDataDir())

		oldName := args[0]
		newName := args[1]

		// If not valid name, return an error
		if ok, err := isValidName(newName); !ok {
			reportErrorln(err)
		}

		// If the old name isn't in use, return an error
		if !accountList.isTaken(oldName) {
			reportErrorf(errorNameDoesntExist, oldName)
		}

		// If the new name isn't available, return an error
		if accountList.isTaken(newName) {
			reportErrorf(errorNameAlreadyTaken, newName)
		}

		// Otherwise, rename
		accountList.rename(oldName, newName)
		reportInfof(infoRenamedAccount, oldName, newName)
	},
}

var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new account",
	Long:  `Coordinates the creation of a new account with KMD. The name specified here is stored in a local configuration file and is only used by goal when working against that specific node instance.`,
	Args:  cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		accountList := makeAccountsList(ensureSingleDataDir())
		// Choose an account name
		if len(args) == 0 {
			accountName = accountList.getUnnamed()
		} else {
			accountName = args[0]
		}

		// If not valid name, return an error
		if ok, err := isValidName(accountName); !ok {
			reportErrorln(err)
		}

		// Ensure the user's name choice isn't taken
		if accountList.isTaken(accountName) {
			reportErrorf(errorNameAlreadyTaken, accountName)
		}

		dataDir := ensureSingleDataDir()

		// Get a wallet handle
		wh := ensureWalletHandle(dataDir, walletName)

		// Generate a new address in the default wallet
		client := ensureKmdClient(dataDir)
		genAddr, err := client.GenerateAddress(wh)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		// Add account to list
		accountList.addAccount(accountName, genAddr)

		// Set account to default if required
		if defaultAccount {
			accountList.setDefault(accountName)
		}

		reportInfof(infoCreatedNewAccount, genAddr)
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete an account",
	Long:  `Delete the indicated account. The key management daemon will no longer know about this account, although the account will still exist on the network.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)

		client := ensureKmdClient(dataDir)
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)

		err := client.DeleteAccount(wh, pw, accountAddress)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		accountList.removeAccount(accountAddress)
	},
}

var newMultisigCmd = &cobra.Command{
	Use:   "new [address 1] [address 2]...",
	Short: "Create a new multisig account",
	Long:  `Create a new multisig account from a list of existing non-multisig addresses`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)

		// Get a wallet handle to the default wallet
		client := ensureKmdClient(dataDir)

		// Get a wallet handle
		wh := ensureWalletHandle(dataDir, walletName)

		// Detect duplicate PKs
		duplicateDetector := make(map[string]int)
		for _, addrStr := range args {
			duplicateDetector[addrStr]++
		}
		duplicatesDetected := false
		for _, counter := range duplicateDetector {
			if counter > 1 {
				duplicatesDetected = true
				break
			}
		}
		if duplicatesDetected {
			reportWarnln(warnMultisigDuplicatesDetected)
		}
		// Generate a new address in the default wallet
		addr, err := client.CreateMultisigAccount(wh, threshold, args)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		// Add account to list
		accountList.addAccount(accountList.getUnnamed(), addr)

		reportInfof(infoCreatedNewAccount, addr)
	},
}

var deleteMultisigCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a multisig account",
	Long:  `Delete a multisig account. Like ordinary account delete, the local node will no longer know about the account, but it may still exist on the network.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)

		client := ensureKmdClient(dataDir)
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)

		err := client.DeleteMultisigAccount(wh, pw, accountAddress)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		accountList.removeAccount(accountAddress)
	},
}

var infoMultisigCmd = &cobra.Command{
	Use:   "info",
	Short: "Print information about a multisig account",
	Long:  `Print information about a multisig account, such as its Algorand multisig version, or the number of keys needed to validate a transaction from the multisig account.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		client := ensureKmdClient(dataDir)
		wh := ensureWalletHandle(dataDir, walletName)

		multisigInfo, err := client.LookupMultisigAccount(wh, accountAddress)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		fmt.Printf("Version: %d\n", multisigInfo.Version)
		fmt.Printf("Threshold: %d\n", multisigInfo.Threshold)
		fmt.Printf("Public keys:\n")
		for _, pk := range multisigInfo.PKs {
			fmt.Printf("  %s\n", pk)
		}
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Show the list of Algorand accounts on this machine",
	Long:  `Show the list of Algorand accounts on this machine. Indicates whether the account is [offline] or [online], and if the account is the default account for goal. Also displays account information with --info.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)

		// Get a wallet handle to the specified wallet
		wh := ensureWalletHandle(dataDir, walletName)

		// List the addresses in the wallet
		client := ensureKmdClient(dataDir)
		addrs, err := client.ListAddressesWithInfo(wh)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		// Special response if there are no addresses
		if len(addrs) == 0 {
			reportInfoln(infoNoAccounts)
			os.Exit(0)
		}

		accountInfoError := false

		// For each address, request information about it from algod
		for _, addr := range addrs {
			response, _ := client.AccountInformation(addr.Addr)
			// it's okay to proceed without algod info

			// Display this information to the user
			if addr.Multisig {
				multisigInfo, err := client.LookupMultisigAccount(wh, addr.Addr)
				if err != nil {
					fmt.Println("multisig lookup err")
					reportErrorf(errorRequestFail, err)
				}

				accountList.outputAccount(addr.Addr, response, &multisigInfo)
			} else {
				accountList.outputAccount(addr.Addr, response, nil)
			}

			if listAccountInfo {
				hasError := printAccountInfo(client, addr.Addr, response)
				accountInfoError = accountInfoError || hasError
			}
		}

		if accountInfoError {
			os.Exit(1)
		}
	},
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Retrieve information about the assets and applications belonging to the specified account",
	Long:  `Retrieve information about the assets and applications the specified account has created or opted into.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		client := ensureAlgodClient(dataDir)
		response, err := client.AccountInformation(accountAddress)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		hasError := printAccountInfo(client, accountAddress, response)
		if hasError {
			os.Exit(1)
		}
	},
}

func sortUint64Slice(slice []uint64) {
	sort.Slice(slice, func(i, j int) bool {
		return slice[i] < slice[j]
	})
}

func printAccountInfo(client libgoal.Client, address string, account v1.Account) bool {
	createdAssets := []uint64{}
	for id := range account.AssetParams {
		createdAssets = append(createdAssets, id)
	}
	sortUint64Slice(createdAssets)

	heldAssets := []uint64{}
	for id := range account.Assets {
		heldAssets = append(heldAssets, id)
	}
	sortUint64Slice(heldAssets)

	createdApps := []uint64{}
	for id := range account.AppParams {
		createdApps = append(createdApps, id)
	}
	sortUint64Slice(createdApps)

	optedInApps := []uint64{}
	for id := range account.AppLocalStates {
		optedInApps = append(optedInApps, id)
	}
	sortUint64Slice(optedInApps)

	report := &strings.Builder{}
	errorReport := &strings.Builder{}
	hasError := false

	fmt.Fprintln(report, "Created Assets:")
	if len(createdAssets) == 0 {
		fmt.Fprintln(report, "\t<none>")
	}
	for _, id := range createdAssets {
		assetParams := account.AssetParams[id]

		name := assetParams.AssetName
		if len(name) == 0 {
			name = "<unnamed>"
		}
		_, name = unicodePrintable(name)
		units := assetParams.UnitName
		if len(units) == 0 {
			units = "units"
		}
		_, units = unicodePrintable(units)
		total := assetDecimalsFmt(assetParams.Total, assetParams.Decimals)
		url := ""
		if len(assetParams.URL) != 0 {
			url = fmt.Sprintf(", %s", assetParams.URL)
		}

		fmt.Fprintf(report, "\tID %d, %s, supply %s %s%s\n", id, name, total, units, url)
	}

	fmt.Fprintln(report, "Held Assets:")
	if len(heldAssets) == 0 {
		fmt.Fprintln(report, "\t<none>")
	}
	for _, id := range heldAssets {
		assetHolding := account.Assets[id]
		assetParams, err := client.AssetInformation(id)
		if err != nil {
			hasError = true
			fmt.Fprintf(errorReport, "Error: Unable to retrieve asset information for asset %d referred to by account %s: %v\n", id, address, err)
			fmt.Fprintf(report, "\tID %d, error\n", id)
		}

		amount := assetDecimalsFmt(assetHolding.Amount, assetParams.Decimals)

		assetName := assetParams.AssetName
		if len(assetName) == 0 {
			assetName = "<unnamed>"
		}
		_, assetName = unicodePrintable(assetName)

		unitName := assetParams.UnitName
		if len(unitName) == 0 {
			unitName = "units"
		}
		_, unitName = unicodePrintable(unitName)

		frozen := ""
		if assetHolding.Frozen {
			frozen = " (frozen)"
		}

		fmt.Fprintf(report, "\tID %d, %s, balance %s %s%s\n", id, assetName, amount, unitName, frozen)
	}

	fmt.Fprintln(report, "Created Apps:")
	if len(createdApps) == 0 {
		fmt.Fprintln(report, "\t<none>")
	}
	for _, id := range createdApps {
		appParams := account.AppParams[id]
		usedInts := 0
		usedBytes := 0
		for _, value := range appParams.GlobalState {
			if value.Type == "u" {
				usedInts++
			} else {
				usedBytes++
			}
		}
		fmt.Fprintf(report, "\tID %d, global state used %d/%d uints, %d/%d byte slices\n", id, usedInts, appParams.GlobalStateSchema.NumUint, usedBytes, appParams.GlobalStateSchema.NumByteSlice)
	}

	fmt.Fprintln(report, "Opted In Apps:")
	if len(optedInApps) == 0 {
		fmt.Fprintln(report, "\t<none>")
	}
	for _, id := range optedInApps {
		localState := account.AppLocalStates[id]
		usedInts := 0
		usedBytes := 0
		for _, value := range localState.KeyValue {
			if value.Type == "u" {
				usedInts++
			} else {
				usedBytes++
			}
		}
		fmt.Fprintf(report, "\tID %d, local state used %d/%d uints, %d/%d byte slices\n", id, usedInts, localState.Schema.NumUint, usedBytes, localState.Schema.NumByteSlice)
	}

	if hasError {
		fmt.Fprint(os.Stderr, errorReport.String())
	}
	fmt.Print(report.String())
	return hasError
}

var balanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Retrieve the balances for the specified account",
	Long:  `Retrieve the balance record for the specified account. Algo balance is displayed in microAlgos.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		client := ensureAlgodClient(dataDir)
		response, err := client.AccountInformation(accountAddress)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		fmt.Printf("%v microAlgos\n", response.Amount)
	},
}

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump the balance record for the specified account",
	Long:  `Dump the balance record for the specified account to terminal as JSON or to a file as MessagePack.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		client := ensureAlgodClient(dataDir)
		rawAddress, err := basics.UnmarshalChecksumAddress(accountAddress)
		if err != nil {
			reportErrorf(errorParseAddr, err)
		}
		accountData, err := client.AccountData(accountAddress)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		br := basics.BalanceRecord{Addr: rawAddress, AccountData: accountData}
		if len(dumpOutFile) > 0 {
			data := protocol.Encode(&br)
			writeFile(dumpOutFile, data, 0644)
		} else {
			data := protocol.EncodeJSONStrict(&br)
			fmt.Println(string(data))
		}
	},
}

var rewardsCmd = &cobra.Command{
	Use:   "rewards",
	Short: "Retrieve the rewards for the specified account",
	Long:  `Retrieve the rewards for the specified account, including pending rewards. Units displayed are microAlgos.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		client := ensureAlgodClient(dataDir)
		response, err := client.AccountInformation(accountAddress)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		fmt.Printf("%v microAlgos\n", response.Rewards)
	},
}

var changeOnlineCmd = &cobra.Command{
	Use:   "changeonlinestatus",
	Short: "Change online status for the specified account",
	Long:  `Change online status for the specified account. Set online should be 1 to set online, 0 to set offline. The broadcast transaction will be valid for a limited number of rounds. goal will provide the TXID of the transaction if successful. Going online requires that the given account has a valid participation key. If the participation key is specified using --partkeyfile, you must separately install the participation key from that file using "goal account installpartkey".`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		checkTxValidityPeriodCmdFlags(cmd)

		if accountAddress == "" && partKeyFile == "" {
			fmt.Printf("Must specify one of --address or --partkeyfile\n")
			os.Exit(1)
		}

		if partKeyFile != "" && !online {
			fmt.Printf("Going offline does not support --partkeyfile\n")
			os.Exit(1)
		}

		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		var part *algodAcct.Participation
		if partKeyFile != "" {
			partdb, err := db.MakeErasableAccessor(partKeyFile)
			if err != nil {
				fmt.Printf("Cannot open partkey %s: %v\n", partKeyFile, err)
				os.Exit(1)
			}

			partkey, err := algodAcct.RestoreParticipation(partdb)
			if err != nil {
				fmt.Printf("Cannot load partkey %s: %v\n", partKeyFile, err)
				os.Exit(1)
			}

			part = &partkey.Participation
			if accountAddress == "" {
				accountAddress = part.Parent.String()
			}
		}

		firstTxRound, lastTxRound, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf(err.Error())
		}
		err = changeAccountOnlineStatus(
			accountAddress, part, online, statusChangeTxFile, walletName,
			firstTxRound, lastTxRound, transactionFee, scLeaseBytes(cmd), dataDir, client,
		)
		if err != nil {
			reportErrorf(err.Error())
		}
	},
}

func changeAccountOnlineStatus(acct string, part *algodAcct.Participation, goOnline bool, txFile string, wallet string, firstTxRound, lastTxRound, fee uint64, leaseBytes [32]byte, dataDir string, client libgoal.Client) error {
	// Generate an unsigned online/offline tx
	var utx transactions.Transaction
	var err error
	if goOnline {
		utx, err = client.MakeUnsignedGoOnlineTx(acct, part, firstTxRound, lastTxRound, fee, leaseBytes)
	} else {
		utx, err = client.MakeUnsignedGoOfflineTx(acct, firstTxRound, lastTxRound, fee, leaseBytes)
	}
	if err != nil {
		return err
	}

	if txFile != "" {
		return writeTxnToFile(client, false, dataDir, wallet, utx, txFile)
	}

	// Sign & broadcast the transaction
	wh, pw := ensureWalletHandleMaybePassword(dataDir, wallet, true)
	txid, err := client.SignAndBroadcastTransaction(wh, pw, utx)
	if err != nil {
		return fmt.Errorf(errorOnlineTX, err)
	}
	fmt.Printf("Transaction id for status change transaction: %s\n", txid)

	if noWaitAfterSend {
		fmt.Println("Note: status will not change until transaction is finalized")
		return nil
	}

	_, err = waitForCommit(client, txid, lastTxRound)
	return err
}

var addParticipationKeyCmd = &cobra.Command{
	Use:   "addpartkey",
	Short: "Generate a participation key for the specified account",
	Long:  `Generate a participation key for the specified account. This participation key can then be used for going online and participating in consensus.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()

		if partKeyOutDir != "" && !util.IsDir(partKeyOutDir) {
			reportErrorf(errorDirectoryNotExist, partKeyOutDir)
		}

		// Generate a participation keys database and install it
		client := ensureFullClient(dataDir)

		_, _, err := client.GenParticipationKeysTo(accountAddress, roundFirstValid, roundLastValid, keyDilution, partKeyOutDir)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		fmt.Println("Participation key generation successful")
	},
}

var installParticipationKeyCmd = &cobra.Command{
	Use:   "installpartkey",
	Short: "Install a participation key",
	Long:  `Install a participation key from a partkey file. Intended for use with participation key files generated by "algokey part generate". Does not change the online status of an account or register the participation key; use "goal account changeonlinestatus" for doing so. Deletes input key file on successful install to ensure forward security.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if !partKeyDeleteInput {
			fmt.Println(
				`The installpartkey command deletes the input participation file on
successful installation.  Please acknowledge this by passing the
"--delete-input" flag to the installpartkey command.  You can make
a copy of the input file if needed, but please keep in mind that
participation keys must be securely deleted for each round, to ensure
forward security.  Storing old participation keys compromises overall
system security.

No --delete-input flag specified, exiting without installing key.`)
			os.Exit(1)
		}

		dataDir := ensureSingleDataDir()

		client := ensureAlgodClient(dataDir)
		_, _, err := client.InstallParticipationKeys(partKeyFile)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		fmt.Println("Participation key installed successfully")
	},
}

var renewParticipationKeyCmd = &cobra.Command{
	Use:   "renewpartkey",
	Short: "Renew an account's participation key",
	Long:  `Generate a participation key for the specified account and issue the necessary transaction to register it.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()

		client := ensureAlgodClient(dataDir)

		currentRound, err := client.CurrentRound()
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		params, err := client.SuggestedParams()
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		proto := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]

		if roundLastValid <= (currentRound + proto.MaxTxnLife) {
			reportErrorf(errLastRoundInvalid, currentRound)
		}

		// Make sure we don't already have a partkey valid for (or after) specified roundLastValid
		parts, err := client.ListParticipationKeys()
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		for _, part := range parts {
			if part.Address().String() == accountAddress {
				if part.LastValid >= basics.Round(roundLastValid) {
					reportErrorf(errExistingPartKey, roundLastValid, part.LastValid)
				}
			}
		}

		err = generateAndRegisterPartKey(accountAddress, currentRound, roundLastValid, transactionFee, scLeaseBytes(cmd), keyDilution, walletName, dataDir, client)
		if err != nil {
			reportErrorf(err.Error())
		}
	},
}

func generateAndRegisterPartKey(address string, currentRound, lastValidRound uint64, fee uint64, leaseBytes [32]byte, dilution uint64, wallet string, dataDir string, client libgoal.Client) error {
	// Generate a participation keys database and install it
	part, keyPath, err := client.GenParticipationKeysTo(address, currentRound, lastValidRound, dilution, "")
	if err != nil {
		return fmt.Errorf(errorRequestFail, err)
	}
	fmt.Printf("  Generated participation key for %s (Valid %d - %d)\n", address, currentRound, lastValidRound)

	// Now register it as our new online participation key
	goOnline := true
	txFile := ""
	err = changeAccountOnlineStatus(address, &part, goOnline, txFile, wallet, currentRound, lastValidRound, fee, leaseBytes, dataDir, client)
	if err != nil {
		os.Remove(keyPath)
		fmt.Fprintf(os.Stderr, "  Error registering keys - deleting newly-generated key file: %s\n", keyPath)
	}
	return err
}

var renewAllParticipationKeyCmd = &cobra.Command{
	Use:   "renewallpartkeys",
	Short: "Renew all existing participation keys",
	Long:  `Generate new participation keys for all existing accounts with participation keys and issue the necessary transactions to register them.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		onDataDirs(func(dataDir string) {
			fmt.Printf("Renewing participation keys in %s...\n", dataDir)
			err := renewPartKeysInDir(dataDir, roundLastValid, transactionFee, scLeaseBytes(cmd), keyDilution, walletName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: %s\n", err)
			}
		})
	},
}

func renewPartKeysInDir(dataDir string, lastValidRound uint64, fee uint64, leaseBytes [32]byte, dilution uint64, wallet string) error {
	client := ensureAlgodClient(dataDir)

	// Build list of accounts to renew from all accounts with part keys present
	parts, err := client.ListParticipationKeys()
	if err != nil {
		return fmt.Errorf(errorRequestFail, err)
	}
	renewAccounts := make(map[basics.Address]algodAcct.Participation)
	for _, part := range parts {
		if existing, has := renewAccounts[part.Address()]; has {
			if existing.LastValid >= part.LastValid {
				// We already saw a partkey that expires later
				continue
			}
		}
		renewAccounts[part.Address()] = part
	}

	currentRound, err := client.CurrentRound()
	if err != nil {
		return fmt.Errorf(errorRequestFail, err)
	}

	params, err := client.SuggestedParams()
	if err != nil {
		return fmt.Errorf(errorRequestFail, err)
	}
	proto := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]

	if lastValidRound <= (currentRound + proto.MaxTxnLife) {
		return fmt.Errorf(errLastRoundInvalid, currentRound)
	}

	var anyErrors bool

	// Now go through each account and if it doesn't have a part key that's valid
	// at least through lastValidRound, generate a new key and register it.
	// Make sure we don't already have a partkey valid for (or after) specified roundLastValid
	for _, renewPart := range renewAccounts {
		if renewPart.LastValid >= basics.Round(lastValidRound) {
			fmt.Printf("  Skipping account %s: Already has a part key valid beyond %d (currently %d)\n", renewPart.Address(), lastValidRound, renewPart.LastValid)
			continue
		}

		// If the account's latest partkey expired before the current round, don't automatically renew and instead instruct the user to explicitly renew it.
		if renewPart.LastValid < basics.Round(lastValidRound) {
			fmt.Printf("  Skipping account %s: This account has part keys that have expired.  Please renew this account explicitly using 'renewpartkey'\n", renewPart.Address())
			continue
		}

		address := renewPart.Address().String()
		err = generateAndRegisterPartKey(address, currentRound, lastValidRound, fee, leaseBytes, dilution, wallet, dataDir, client)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error renewing part key for account %s: %v\n", address, err)
			anyErrors = true
		}
	}
	if anyErrors {
		return fmt.Errorf("one or more renewal attempts had errors")
	}
	return nil
}

var listParticipationKeysCmd = &cobra.Command{
	Use:   "listpartkeys",
	Short: "List participation keys",
	Long:  `List all participation keys tracked by algod, with additional information such as key validity period.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()

		client := ensureGoalClient(dataDir, libgoal.DynamicClient)
		parts, err := client.ListParticipationKeys()
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		var filenames []string
		for fn := range parts {
			filenames = append(filenames, fn)
		}
		sort.Strings(filenames)

		rowFormat := "%-10s\t%-80s\t%-60s\t%12s\t%12s\t%12s\n"
		fmt.Printf(rowFormat, "Registered", "Filename", "Parent address", "First round", "Last round", "First key")
		for _, fn := range filenames {
			onlineInfoStr := "unknown"
			onlineAccountInfo, err := client.AccountInformation(parts[fn].Address().GetUserAddress())
			if err == nil {
				votingBytes := parts[fn].Voting.OneTimeSignatureVerifier
				vrfBytes := parts[fn].VRF.PK
				if onlineAccountInfo.Participation != nil &&
					(string(onlineAccountInfo.Participation.ParticipationPK) == string(votingBytes[:])) &&
					(string(onlineAccountInfo.Participation.VRFPK) == string(vrfBytes[:])) &&
					(onlineAccountInfo.Participation.VoteFirst == uint64(parts[fn].FirstValid)) &&
					(onlineAccountInfo.Participation.VoteLast == uint64(parts[fn].LastValid)) &&
					(onlineAccountInfo.Participation.VoteKeyDilution == parts[fn].KeyDilution) {
					onlineInfoStr = "yes"
				} else {
					onlineInfoStr = "no"
				}
			}
			// it's okay to proceed without algod info
			first, last := parts[fn].ValidInterval()
			fmt.Printf(rowFormat, onlineInfoStr, fn, parts[fn].Address().GetUserAddress(),
				fmt.Sprintf("%d", first),
				fmt.Sprintf("%d", last),
				fmt.Sprintf("%d.%d", parts[fn].Voting.FirstBatch, parts[fn].Voting.FirstOffset))
		}
	},
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an account key from mnemonic",
	Long:  "Import an account key from a mnemonic generated by the export command or by algokey (NOT a mnemonic from the goal wallet command). The imported account will be listed alongside your wallet-generated accounts, but will not be tied to your wallet.",
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)
		// Choose an account name
		if len(args) == 0 {
			accountName = accountList.getUnnamed()
		} else {
			accountName = args[0]
		}

		// If not valid name, return an error
		if ok, err := isValidName(accountName); !ok {
			reportErrorln(err)
		}

		// Ensure the user's name choice isn't taken
		if accountList.isTaken(accountName) {
			reportErrorf(errorNameAlreadyTaken, accountName)
		}

		client := ensureKmdClient(dataDir)
		wh := ensureWalletHandle(dataDir, walletName)
		//wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)

		if mnemonic == "" {
			fmt.Println(infoRecoveryPrompt)
			reader := bufio.NewReader(os.Stdin)
			resp, err := reader.ReadString('\n')
			resp = strings.TrimSpace(resp)
			if err != nil {
				reportErrorf(errorFailedToReadResponse, err)
			}
			mnemonic = resp
		}
		var key []byte
		key, err := passphrase.MnemonicToKey(mnemonic)
		if err != nil {
			reportErrorf(errorBadMnemonic, err)
		}

		importedKey, err := client.ImportKey(wh, key)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		} else {
			reportInfof(infoImportedKey, importedKey.Address)

			accountList.addAccount(accountName, importedKey.Address)
			if importDefault {
				accountList.setDefault(accountName)
			}
		}
	},
}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export an account key for use with account import",
	Long:  "Export an account mnemonic seed, for use with account import. This exports the seed for a single account and should NOT be confused with the wallet mnemonic.",
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		client := ensureKmdClient(dataDir)

		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
		passwordString := string(pw)

		response, err := client.ExportKey(wh, passwordString, accountAddress)

		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		seed, err := crypto.SecretKeyToSeed(response.PrivateKey)

		if err != nil {
			reportErrorf(errorSeedConversion, accountAddress, err)
		}

		privKeyAsMnemonic, err := passphrase.KeyToMnemonic(seed[:])

		if err != nil {
			reportErrorf(errorMnemonicConversion, accountAddress, err)
		}

		reportInfof(infoExportedKey, accountAddress, privKeyAsMnemonic)
	},
}

var importRootKeysCmd = &cobra.Command{
	Use:   "importrootkey",
	Short: "Import .rootkey files from the data directory into a kmd wallet",
	Long:  "Import .rootkey files from the data directory into a kmd wallet. This is analogous to using the import command with an account seed mnemonic: the imported account will be displayed alongside your wallet-derived accounts, but will not be tied to your wallet mnemonic.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := ensureSingleDataDir()
		// Generate a participation keys database and install it
		client := ensureKmdClient(dataDir)

		genID, err := client.GenesisID()
		if err != nil {
			return
		}

		keyDir := filepath.Join(dataDir, genID)
		files, err := ioutil.ReadDir(keyDir)
		if err != nil {
			return
		}

		// For each of these files
		cnt := 0
		for _, info := range files {
			var handle db.Accessor

			// If it can't be a participation key database, skip it
			if !config.IsRootKeyFilename(info.Name()) {
				continue
			}

			filename := info.Name()

			// Fetch a handle to this database
			handle, err = db.MakeErasableAccessor(filepath.Join(keyDir, filename))
			if err != nil {
				// Couldn't open it, skip it
				err = nil
				continue
			}

			// Fetch an account.Participation from the database
			root, err := algodAcct.RestoreRoot(handle)
			handle.Close()
			if err != nil {
				// Couldn't read it, skip it
				err = nil
				continue
			}

			secretKey := root.Secrets().SK

			// Determine which wallet to import into
			var wh []byte
			if unencryptedWallet {
				wh, err = client.GetUnencryptedWalletHandle()
				if err != nil {
					reportErrorf(errorRequestFail, err)
				}
			} else {
				wh = ensureWalletHandle(dataDir, walletName)
			}

			resp, err := client.ImportKey(wh, secretKey[:])
			if err != nil {
				// If error is 'like' "key already exists", treat as warning and not an error
				if strings.Contains(err.Error(), "key already exists") {
					reportWarnf(errorRequestFail, err.Error()+"\n > Key File: "+filename)
				} else {
					reportErrorf(errorRequestFail, err)
				}
			} else {
				// Count the number of keys imported
				cnt++
				reportInfof(infoImportedKey, resp.Address)
			}
		}

		// Provide feedback on how many keys were imported
		plural := "s"
		if cnt == 1 {
			plural = ""
		}
		reportInfof(infoImportedNKeys, cnt, plural)
	},
}

type partkeyInfo struct {
	_struct         struct{}                        `codec:",omitempty,omitemptyarray"`
	Address         string                          `codec:"acct"`
	FirstValid      basics.Round                    `codec:"first"`
	LastValid       basics.Round                    `codec:"last"`
	VoteID          crypto.OneTimeSignatureVerifier `codec:"vote"`
	SelectionID     crypto.VRFVerifier              `codec:"sel"`
	BlockProofID    crypto.VerifyingKey             `codec:"blockProof"`
	VoteKeyDilution uint64                          `codec:"voteKD"`
}

var partkeyInfoCmd = &cobra.Command{
	Use:   "partkeyinfo",
	Short: "Output details about all available part keys",
	Long:  `Output details about all available part keys in the specified data directory(ies), such as key validity period.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {

		onDataDirs(func(dataDir string) {
			fmt.Printf("Dumping participation key info from %s...\n", dataDir)
			client := ensureGoalClient(dataDir, libgoal.DynamicClient)

			// Make sure we don't already have a partkey valid for (or after) specified roundLastValid
			parts, err := client.ListParticipationKeys()
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			for filename, part := range parts {
				fmt.Println("------------------------------------------------------------------")

				info := partkeyInfo{
					Address:         part.Address().String(),
					FirstValid:      part.FirstValid,
					LastValid:       part.LastValid,
					VoteID:          part.VotingSecrets().OneTimeSignatureVerifier,
					SelectionID:     part.VRFSecrets().PK,
					VoteKeyDilution: part.KeyDilution,
				}
				if certSigner := part.BlockProofSigner(); certSigner != nil {
					info.BlockProofID = certSigner.GetSigner().GetVerifyingKey()
				}
				infoString := protocol.EncodeJSON(&info)
				fmt.Printf("File: %s\n%s\n", filename, string(infoString))
			}
		})
	},
}

var markNonparticipatingCmd = &cobra.Command{
	Use:   "marknonparticipating",
	Short: "Permanently mark an account as not participating (i.e. offline and earns no rewards)",
	Long:  "Permanently mark an account as not participating (as opposed to Online or Offline). Once marked, the account can never go online or offline, it is forever nonparticipating, and it will never earn rewards on its balance.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {

		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)
		firstTxRound, lastTxRound, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf(errorConstructingTX, err)
		}
		utx, err := client.MakeUnsignedBecomeNonparticipatingTx(accountAddress, firstTxRound, lastTxRound, transactionFee)
		if err != nil {
			reportErrorf(errorConstructingTX, err)
		}

		if statusChangeTxFile != "" {
			err = writeTxnToFile(client, false, dataDir, walletName, utx, statusChangeTxFile)
			if err != nil {
				reportErrorf(fileWriteError, statusChangeTxFile, err)
			}
			return
		}

		// Sign & broadcast the transaction
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
		txid, err := client.SignAndBroadcastTransaction(wh, pw, utx)
		if err != nil {
			reportErrorf(errorOnlineTX, err)
		}
		fmt.Printf("Transaction id for mark-nonparticipating transaction: %s\n", txid)

		if noWaitAfterSend {
			fmt.Println("Note: status will not change until transaction is finalized")
			return
		}

		_, err = waitForCommit(client, txid, lastTxRound)
		if err != nil {
			reportErrorf("error waiting for transaction to be committed: %v", err)
		}
	},
}
