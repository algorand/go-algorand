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
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
	apiClient "github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	algodAcct "github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/libgoal/participation"
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
	roundFirstValid    basics.Round
	roundLastValid     basics.Round
	keyDilution        uint64
	threshold          uint8
	partKeyOutDir      string
	partKeyFile        string
	partKeyDeleteInput bool
	importDefault      bool
	mnemonic           string
	dumpOutFile        string
	listAccountInfo    bool
	onlyShowAssetIDs   bool
	partKeyIDToDelete  string

	next  string
	limit uint64
)

func init() {
	accountCmd.AddCommand(newCmd)
	accountCmd.AddCommand(deleteCmd)
	accountCmd.AddCommand(listCmd)
	accountCmd.AddCommand(renameCmd)
	accountCmd.AddCommand(infoCmd)
	accountCmd.AddCommand(assetDetailsCmd)
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
	accountCmd.AddCommand(deletePartKeyCmd)

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
	infoCmd.Flags().BoolVar(&onlyShowAssetIDs, "onlyShowAssetIDs", false, "Only show ASA IDs and not pull asset metadata")

	// Asset details flags
	assetDetailsCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to look up (required)")
	assetDetailsCmd.MarkFlagRequired("address")
	assetDetailsCmd.Flags().StringVarP(&next, "next", "n", "", "The next asset index to use for pagination")
	assetDetailsCmd.Flags().Uint64VarP(&limit, "limit", "l", 0, "The maximum number of assets to return")

	// Balance flags
	balanceCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to retrieve balance (required)")
	balanceCmd.MarkFlagRequired("address")

	// Rewards flags
	rewardsCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to retrieve rewards (required)")
	rewardsCmd.MarkFlagRequired("address")

	// changeOnlineStatus flags
	changeOnlineCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to change (required if no --partkeyfile)")
	changeOnlineCmd.Flags().StringVarP(&partKeyFile, "partkeyfile", "", "", "Participation key file (required if no --address)")
	changeOnlineCmd.Flags().StringVarP(&signerAddress, "signer", "S", "", "Address of key to sign with, if different due to rekeying")
	changeOnlineCmd.Flags().BoolVarP(&online, "online", "o", true, "Set this account to online or offline")
	changeOnlineCmd.Flags().Uint64VarP(&transactionFee, "fee", "f", 0, "The Fee to set on the status change transaction (defaults to suggested fee)")
	changeOnlineCmd.Flags().Uint64VarP((*uint64)(&firstValid), "firstRound", "", 0, "")
	changeOnlineCmd.Flags().Uint64VarP((*uint64)(&firstValid), "firstvalid", "", 0, "FirstValid for the status change transaction (0 for current)")
	changeOnlineCmd.Flags().Uint64VarP((*uint64)(&numValidRounds), "validRounds", "", 0, "")
	changeOnlineCmd.Flags().Uint64VarP((*uint64)(&numValidRounds), "validrounds", "v", 0, "The validity period for the status change transaction")
	changeOnlineCmd.Flags().Uint64Var((*uint64)(&lastValid), "lastvalid", 0, "The last round where the transaction may be committed to the ledger")
	changeOnlineCmd.Flags().StringVarP(&statusChangeLease, "lease", "x", "", "Lease value (base64, optional): no transaction may also acquire this lease until lastvalid")
	changeOnlineCmd.Flags().StringVarP(&statusChangeTxFile, "txfile", "t", "", "Write status change transaction to this file")
	changeOnlineCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	changeOnlineCmd.Flags().MarkDeprecated("firstRound", "use --firstvalid instead")
	changeOnlineCmd.Flags().MarkDeprecated("validRounds", "use --validrounds instead")

	// addParticipationKey flags
	addParticipationKeyCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account to associate with the generated partkey")
	addParticipationKeyCmd.MarkFlagRequired("address")
	addParticipationKeyCmd.Flags().Uint64VarP((*uint64)(&roundFirstValid), "roundFirstValid", "", 0, "The first round for which the generated partkey will be valid")
	addParticipationKeyCmd.MarkFlagRequired("roundFirstValid")
	addParticipationKeyCmd.Flags().Uint64VarP((*uint64)(&roundLastValid), "roundLastValid", "", 0, "The last round for which the generated partkey will be valid")
	addParticipationKeyCmd.MarkFlagRequired("roundLastValid")
	addParticipationKeyCmd.Flags().StringVarP(&partKeyOutDir, "outdir", "o", "", "Save participation key file to specified output directory to (for offline creation)")
	addParticipationKeyCmd.Flags().Uint64VarP(&keyDilution, "keyDilution", "", 0, "Key dilution for two-level participation keys (defaults to sqrt of validity window)")

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
	renewParticipationKeyCmd.Flags().Uint64VarP((*uint64)(&roundLastValid), "roundLastValid", "", 0, "The last round for which the generated partkey will be valid")
	renewParticipationKeyCmd.MarkFlagRequired("roundLastValid")
	renewParticipationKeyCmd.Flags().Uint64VarP(&keyDilution, "keyDilution", "", 0, "Key dilution for two-level participation keys")
	renewParticipationKeyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")

	// renewAllParticipationKeyCmd
	renewAllParticipationKeyCmd.Flags().Uint64VarP(&transactionFee, "fee", "f", 0, "The Fee to set on the status change transactions (defaults to suggested fee)")
	renewAllParticipationKeyCmd.Flags().Uint64VarP((*uint64)(&roundLastValid), "roundLastValid", "", 0, "The last round for which the generated partkeys will be valid")
	renewAllParticipationKeyCmd.MarkFlagRequired("roundLastValid")
	renewAllParticipationKeyCmd.Flags().Uint64VarP(&keyDilution, "keyDilution", "", 0, "Key dilution for two-level participation keys")
	renewAllParticipationKeyCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")

	// markNonparticipatingCmd flags
	markNonparticipatingCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to change")
	markNonparticipatingCmd.MarkFlagRequired("address")
	markNonparticipatingCmd.Flags().StringVarP(&signerAddress, "signer", "S", "", "Address of key to sign with, if different from address due to rekeying")
	markNonparticipatingCmd.Flags().Uint64VarP(&transactionFee, "fee", "f", 0, "The Fee to set on the status change transaction (defaults to suggested fee)")
	markNonparticipatingCmd.Flags().Uint64VarP((*uint64)(&firstValid), "firstRound", "", 0, "")
	markNonparticipatingCmd.Flags().Uint64VarP((*uint64)(&firstValid), "firstvalid", "", 0, "FirstValid for the status change transaction (0 for current)")
	markNonparticipatingCmd.Flags().Uint64VarP((*uint64)(&numValidRounds), "validRounds", "", 0, "")
	markNonparticipatingCmd.Flags().Uint64VarP((*uint64)(&numValidRounds), "validrounds", "v", 0, "The validity period for the status change transaction")
	markNonparticipatingCmd.Flags().Uint64Var((*uint64)(&lastValid), "lastvalid", 0, "The last round where the transaction may be committed to the ledger")
	markNonparticipatingCmd.Flags().StringVarP(&statusChangeTxFile, "txfile", "t", "", "Write status change transaction to this file, rather than posting to network")
	markNonparticipatingCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	markNonparticipatingCmd.Flags().MarkDeprecated("firstRound", "use --firstvalid instead")
	markNonparticipatingCmd.Flags().MarkDeprecated("validRounds", "use --validrounds instead")

	dumpCmd.Flags().StringVarP(&dumpOutFile, "outfile", "o", "", "Save balance record to specified output file")
	dumpCmd.Flags().StringVarP(&accountAddress, "address", "a", "", "Account address to retrieve balance (required)")
	balanceCmd.MarkFlagRequired("address")

	// deletePartkeyCmd flags
	deletePartKeyCmd.Flags().StringVarP(&partKeyIDToDelete, "partkeyid", "", "", "Participation Key ID to delete")
	rewardsCmd.MarkFlagRequired("partkeyid")

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
		accountList := makeAccountsList(datadir.EnsureSingleDataDir())

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
		accountList := makeAccountsList(datadir.EnsureSingleDataDir())

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
		accountList := makeAccountsList(datadir.EnsureSingleDataDir())
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

		dataDir := datadir.EnsureSingleDataDir()

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

var deletePartKeyCmd = &cobra.Command{
	Use:   "deletepartkey",
	Short: "Delete a participation key",
	Long:  `Delete the indicated participation key.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()

		client := ensureAlgodClient(dataDir)

		err := client.RemoveParticipationKey(partKeyIDToDelete)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete an account",
	Long:  `Delete the indicated account. The key management daemon will no longer know about this account, although the account will still exist on the network.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()
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
		dataDir := datadir.EnsureSingleDataDir()
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
			reportWarnRawln(warnMultisigDuplicatesDetected)
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
		dataDir := datadir.EnsureSingleDataDir()
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
		dataDir := datadir.EnsureSingleDataDir()
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
		dataDir := datadir.EnsureSingleDataDir()
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
			response, _ := client.AccountInformation(addr.Addr, true)
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
				hasError := printAccountInfo(client, addr.Addr, false, response)
				accountInfoError = accountInfoError || hasError
			}
		}

		if accountInfoError {
			os.Exit(1)
		}
	},
}

var assetDetailsCmd = &cobra.Command{
	Use:   "assetdetails",
	Short: "Retrieve information about the assets belonging to the specified account inclusive of asset metadata",
	Long:  `Retrieve information about the assets the specified account has created or opted into, inclusive of asset metadata.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()
		client := ensureAlgodClient(dataDir)

		var nextPtr *string
		var limitPtr *uint64
		if next != "" {
			nextPtr = &next
		}
		if limit != 0 {
			limitPtr = &limit
		}
		response, err := client.AccountAssetsInformation(accountAddress, nextPtr, limitPtr)

		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		printAccountAssetsInformation(accountAddress, response)

	},
}
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Retrieve information about the assets and applications belonging to the specified account",
	Long:  `Retrieve information about the assets and applications the specified account has created or opted into.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()
		client := ensureAlgodClient(dataDir)
		response, err := client.AccountInformation(accountAddress, true)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		hasError := printAccountInfo(client, accountAddress, onlyShowAssetIDs, response)
		if hasError {
			os.Exit(1)
		}
	},
}

func printAccountInfo(client libgoal.Client, address string, onlyShowAssetIDs bool, account model.Account) bool {
	var createdAssets []model.Asset
	if account.CreatedAssets != nil {
		createdAssets = slices.Clone(*account.CreatedAssets)
		sort.Slice(createdAssets, func(i, j int) bool {
			return createdAssets[i].Index < createdAssets[j].Index
		})
	}

	var heldAssets []model.AssetHolding
	if account.Assets != nil {
		heldAssets = slices.Clone(*account.Assets)
		sort.Slice(heldAssets, func(i, j int) bool {
			return heldAssets[i].AssetID < heldAssets[j].AssetID
		})
	}

	var createdApps []model.Application
	if account.CreatedApps != nil {
		createdApps = slices.Clone(*account.CreatedApps)
		sort.Slice(createdApps, func(i, j int) bool {
			return createdApps[i].Id < createdApps[j].Id
		})
	}

	var optedInApps []model.ApplicationLocalState
	if account.AppsLocalState != nil {
		optedInApps = slices.Clone(*account.AppsLocalState)
		sort.Slice(optedInApps, func(i, j int) bool {
			return optedInApps[i].Id < optedInApps[j].Id
		})
	}

	report := &strings.Builder{}
	errorReport := &strings.Builder{}
	hasError := false

	fmt.Fprintln(report, "Created Assets:")
	if len(createdAssets) == 0 {
		fmt.Fprintln(report, "\t<none>")
	}
	for _, createdAsset := range createdAssets {
		name := "<unnamed>"
		if createdAsset.Params.Name != nil {
			_, name = unicodePrintable(*createdAsset.Params.Name)
		}

		units := "units"
		if createdAsset.Params.UnitName != nil {
			_, units = unicodePrintable(*createdAsset.Params.UnitName)
		}

		total := assetDecimalsFmt(createdAsset.Params.Total, createdAsset.Params.Decimals)

		url := ""
		if createdAsset.Params.Url != nil {
			_, safeURL := unicodePrintable(*createdAsset.Params.Url)
			url = fmt.Sprintf(", %s", safeURL)
		}

		fmt.Fprintf(report, "\tID %d, %s, supply %s %s%s\n", createdAsset.Index, name, total, units, url)
	}

	fmt.Fprintln(report, "Held Assets:")
	if len(heldAssets) == 0 {
		fmt.Fprintln(report, "\t<none>")
	}
	for _, assetHolding := range heldAssets {
		if onlyShowAssetIDs {
			fmt.Fprintf(report, "\tID %d\n", assetHolding.AssetID)
			continue
		}
		assetParams, err := client.AssetInformation(assetHolding.AssetID)
		if err != nil {
			var httpError apiClient.HTTPError
			if errors.As(err, &httpError) && httpError.StatusCode == http.StatusNotFound {
				fmt.Fprintf(report, "\tID %d, <deleted/unknown asset>\n", assetHolding.AssetID)
			} else {
				fmt.Fprintf(errorReport, "Error: Unable to retrieve asset information for asset %d referred to by account %s: %v\n", assetHolding.AssetID, address, err)
				fmt.Fprintf(report, "\tID %d, error\n", assetHolding.AssetID)
				hasError = true
			}
			continue
		}

		amount := assetDecimalsFmt(assetHolding.Amount, assetParams.Params.Decimals)

		assetName := "<unnamed>"
		if assetParams.Params.Name != nil {
			_, assetName = unicodePrintable(*assetParams.Params.Name)
		}

		unitName := "units"
		if assetParams.Params.UnitName != nil {
			_, unitName = unicodePrintable(*assetParams.Params.UnitName)
		}

		frozen := ""
		if assetHolding.IsFrozen {
			frozen = " (frozen)"
		}

		fmt.Fprintf(report, "\tID %d, %s, balance %s %s%s\n", assetHolding.AssetID, assetName, amount, unitName, frozen)
	}

	fmt.Fprintln(report, "Created Apps:")
	if len(createdApps) == 0 {
		fmt.Fprintln(report, "\t<none>")
	}
	for _, app := range createdApps {
		allocatedInts := uint64(0)
		allocatedBytes := uint64(0)
		if app.Params.GlobalStateSchema != nil {
			allocatedInts = app.Params.GlobalStateSchema.NumUint
			allocatedBytes = app.Params.GlobalStateSchema.NumByteSlice
		}

		usedInts := uint64(0)
		usedBytes := uint64(0)
		if app.Params.GlobalState != nil {
			for _, value := range *app.Params.GlobalState {
				if basics.TealType(value.Value.Type) == basics.TealUintType {
					usedInts++
				} else {
					usedBytes++
				}
			}
		}

		extraPages := ""
		if app.Params.ExtraProgramPages != nil && *app.Params.ExtraProgramPages != 0 {
			plural := ""
			if *app.Params.ExtraProgramPages != 1 {
				plural = "s"
			}
			extraPages = fmt.Sprintf(", %d extra page%s", *app.Params.ExtraProgramPages, plural)
		}

		version := uint64(0)
		if app.Params.Version != nil {
			version = *app.Params.Version
		}

		fmt.Fprintf(report, "\tID %d%s, global state used %d/%d uints, %d/%d byte slices, version %d\n", app.Id, extraPages, usedInts, allocatedInts, usedBytes, allocatedBytes, version)
	}

	fmt.Fprintln(report, "Opted In Apps:")
	if len(optedInApps) == 0 {
		fmt.Fprintln(report, "\t<none>")
	}
	for _, localState := range optedInApps {
		allocatedInts := localState.Schema.NumUint
		allocatedBytes := localState.Schema.NumByteSlice

		usedInts := uint64(0)
		usedBytes := uint64(0)
		if localState.KeyValue != nil {
			for _, value := range *localState.KeyValue {
				if basics.TealType(value.Value.Type) == basics.TealUintType {
					usedInts++
				} else {
					usedBytes++
				}
			}
		}
		fmt.Fprintf(report, "\tID %d, local state used %d/%d uints, %d/%d byte slices\n", localState.Id, usedInts, allocatedInts, usedBytes, allocatedBytes)
	}

	fmt.Fprintf(report, "Minimum Balance:\t%v microAlgos\n", account.MinBalance)

	if hasError {
		fmt.Fprint(os.Stderr, errorReport.String())
	}
	fmt.Print(report.String())
	return hasError
}

func printAccountAssetsInformation(address string, response model.AccountAssetsInformationResponse) {
	fmt.Printf("Account: %s\n", address)
	fmt.Printf("Round: %d\n", response.Round)
	if response.NextToken != nil {
		fmt.Printf("NextToken (to retrieve more account assets): %s\n", *response.NextToken)
	}
	fmt.Printf("Assets:\n")
	for _, asset := range *response.AssetHoldings {
		fmt.Printf("  Asset ID: %d\n", asset.AssetHolding.AssetID)

		if asset.AssetParams != nil {
			amount := assetDecimalsFmt(asset.AssetHolding.Amount, asset.AssetParams.Decimals)
			fmt.Printf("    Amount: %s\n", amount)
			fmt.Printf("    IsFrozen: %t\n", asset.AssetHolding.IsFrozen)
			fmt.Printf("  Asset Params:\n")
			fmt.Printf("    Creator: %s\n", asset.AssetParams.Creator)

			name := "<unnamed>"
			if asset.AssetParams.Name != nil {
				_, name = unicodePrintable(*asset.AssetParams.Name)
			}
			fmt.Printf("    Name: %s\n", name)

			units := "units"
			if asset.AssetParams.UnitName != nil {
				_, units = unicodePrintable(*asset.AssetParams.UnitName)
			}
			fmt.Printf("    Units: %s\n", units)
			fmt.Printf("    Total: %d\n", asset.AssetParams.Total)
			fmt.Printf("    Decimals: %d\n", asset.AssetParams.Decimals)
			safeURL := ""
			if asset.AssetParams.Url != nil {
				_, safeURL = unicodePrintable(*asset.AssetParams.Url)
			}
			fmt.Printf("    URL: %s\n", safeURL)
		} else {
			fmt.Printf("    Amount (without formatting): %d\n", asset.AssetHolding.Amount)
			fmt.Printf("    IsFrozen: %t\n", asset.AssetHolding.IsFrozen)
		}
	}
}

var balanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Retrieve the balances for the specified account",
	Long:  `Retrieve the balance record for the specified account. Algo balance is displayed in microAlgos.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()
		client := ensureAlgodClient(dataDir)
		response, err := client.AccountInformation(accountAddress, false)
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
		dataDir := datadir.EnsureSingleDataDir()
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
		dataDir := datadir.EnsureSingleDataDir()
		client := ensureAlgodClient(dataDir)
		response, err := client.AccountInformation(accountAddress, false)
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
			reportErrorf("Must specify one of --address or --partkeyfile\n")
		}

		if partKeyFile != "" && !online {
			reportErrorf("Going offline does not support --partkeyfile\n")
		}

		dataDir := datadir.EnsureSingleDataDir()
		var client libgoal.Client
		if statusChangeTxFile != "" {
			// writing out a txn, don't need kmd
			client = ensureAlgodClient(dataDir)
		} else {
			client = ensureFullClient(dataDir)
		}

		var part *algodAcct.Participation
		if partKeyFile != "" {
			partdb, err := db.MakeErasableAccessor(partKeyFile)
			if err != nil {
				reportErrorf("Cannot open partkey %s: %v\n", partKeyFile, err)
			}

			partkey, err := algodAcct.RestoreParticipation(partdb)
			if err != nil {
				reportErrorf("Cannot load partkey %s: %v\n", partKeyFile, err)
			}

			part = &partkey.Participation
			if accountAddress == "" {
				accountAddress = part.Parent.String()
			}
		}

		firstTxRound, lastTxRound, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorln(err)
		}
		err = changeAccountOnlineStatus(
			accountAddress, online, statusChangeTxFile, walletName,
			firstTxRound, lastTxRound, transactionFee, scLeaseBytes(cmd), dataDir, client,
		)
		if err != nil {
			reportErrorln(err)
		}
	},
}

func changeAccountOnlineStatus(
	acct string, goOnline bool, txFile string, wallet string,
	firstTxRound, lastTxRound basics.Round, fee uint64, leaseBytes [32]byte,
	dataDir string, client libgoal.Client,
) error {
	// Generate an unsigned online/offline tx
	var utx transactions.Transaction
	var err error
	if goOnline {
		utx, err = client.MakeUnsignedGoOnlineTx(acct, firstTxRound, lastTxRound, fee, leaseBytes)
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
	signedTxn, err := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, utx)
	if err != nil {
		return fmt.Errorf(errorSigningTX, err)
	}

	txid, err := client.BroadcastTransaction(signedTxn)
	if err != nil {
		return fmt.Errorf(errorBroadcastingTX, err)
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
	Short: "Generate and install participation key for the specified account",
	Long:  `Generate and install participation key for the specified account. This participation key can then be used for going online and participating in consensus.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()

		if partKeyOutDir != "" && !util.IsDir(partKeyOutDir) {
			reportErrorf(errorDirectoryNotExist, partKeyOutDir)
		}

		// Generate a participation keys database and install it
		client := ensureFullClient(dataDir)

		reportInfof("Please stand by while generating keys. This might take a few minutes...")

		var err error
		var part algodAcct.Participation
		participationGen := func() {
			installFunc := func(keyPath string) error {
				_, installErr := client.AddParticipationKey(keyPath)
				return installErr
			}
			part, _, err = participation.GenParticipationKeysTo(accountAddress, roundFirstValid, roundLastValid, keyDilution, partKeyOutDir, installFunc)
		}

		util.RunFuncWithSpinningCursor(participationGen)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		reportInfof("Participation key generation successful. Participation ID: %s\n", part.ID())

		version := config.GetCurrentVersion()
		fmt.Println("\nGenerated with goal v" + version.String())
	},
}

var installParticipationKeyCmd = &cobra.Command{
	Use:   "installpartkey",
	Short: "Install a participation key",
	Long:  `Install a participation key from a partkey file. Intended for use with participation key files generated by "algokey part generate". Does not change the online status of an account or register the participation key; use "goal account changeonlinestatus" for doing so. Deletes input key file on successful install to ensure forward security.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if !partKeyDeleteInput {
			reportErrorf(
				`The installpartkey command deletes the input participation file on
successful installation.  Please acknowledge this by passing the
"--delete-input" flag to the installpartkey command.  You can make
a copy of the input file if needed, but please keep in mind that
participation keys must be securely deleted for each round, to ensure
forward security.  Storing old participation keys compromises overall
system security.

No --delete-input flag specified, exiting without installing key.`)
		}

		dataDir := datadir.EnsureSingleDataDir()

		client := ensureAlgodClient(dataDir)
		addResponse, err := client.AddParticipationKey(partKeyFile)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		// In an abundance of caution, check for ourselves that the key has been installed.
		if vErr := client.VerifyParticipationKey(time.Minute, addResponse.PartId); vErr != nil {
			vErr = fmt.Errorf("unable to verify key installation. Verify key installation with 'goal account partkeyinfo' and delete '%s', or retry the command. Error: %w", partKeyFile, vErr)
			reportErrorf(errorRequestFail, vErr)
		}

		reportInfof("Participation key installed successfully, Participation ID: %s\n", addResponse.PartId)

		// Delete partKeyFile
		if osErr := os.Remove(partKeyFile); osErr != nil {
			reportErrorf("An error occurred while removing the partkey file, please delete it manually: %s", osErr)
		}
	},
}

var renewParticipationKeyCmd = &cobra.Command{
	Use:   "renewpartkey",
	Short: "Renew an account's participation key",
	Long:  `Generate a participation key for the specified account and issue the necessary transaction to register it.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()

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

		if roundLastValid <= (currentRound + basics.Round(proto.MaxTxnLife)) {
			reportErrorf(errLastRoundInvalid, currentRound)
		}
		txRoundLastValid := currentRound + basics.Round(proto.MaxTxnLife)

		// Make sure we don't already have a partkey valid for (or after) specified roundLastValid
		parts, err := client.ListParticipationKeys()
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		for _, part := range parts {
			if part.Address == accountAddress {
				if part.Key.VoteLastValid >= roundLastValid {
					reportErrorf(errExistingPartKey, roundLastValid, part.Key.VoteLastValid)
				}
			}
		}

		err = generateAndRegisterPartKey(accountAddress, currentRound, roundLastValid, txRoundLastValid, transactionFee, scLeaseBytes(cmd), keyDilution, walletName, dataDir, client)
		if err != nil {
			reportErrorln(err)
		}

		version := config.GetCurrentVersion()
		fmt.Println("\nGenerated with goal v" + version.String())
	},
}

func generateAndRegisterPartKey(address string, currentRound, keyLastValidRound, txLastValidRound basics.Round, fee uint64, leaseBytes [32]byte, dilution uint64, wallet string, dataDir string, client libgoal.Client) error {
	// Generate a participation keys database and install it
	var part algodAcct.Participation
	var keyPath string
	var err error
	genFunc := func() {
		part, keyPath, err = client.GenParticipationKeys(address, currentRound, keyLastValidRound, dilution)
		if err != nil {
			err = fmt.Errorf(errorRequestFail, err)
		}
		fmt.Println("Participation key generation successful")
	}
	fmt.Println("Please stand by while generating keys. This might take a few minutes...")
	util.RunFuncWithSpinningCursor(genFunc)
	if err != nil {
		return err
	}

	// Now register it as our new online participation key
	goOnline := true
	txFile := ""
	err = changeAccountOnlineStatus(address, goOnline, txFile, wallet, currentRound, txLastValidRound, fee, leaseBytes, dataDir, client)
	if err != nil {
		os.Remove(keyPath)
		fmt.Fprintf(os.Stderr, "  Error registering keys - deleting newly-generated key file: %s\n", keyPath)
	}
	fmt.Printf("Participation key installed successfully, Participation ID: %s\n", part.ID())
	return nil
}

var renewAllParticipationKeyCmd = &cobra.Command{
	Use:   "renewallpartkeys",
	Short: "Renew all existing participation keys",
	Long:  `Generate new participation keys for all existing accounts with participation keys and issue the necessary transactions to register them.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		datadir.OnDataDirs(func(dataDir string) {
			fmt.Printf("Renewing participation keys in %s...\n", dataDir)
			err := renewPartKeysInDir(dataDir, roundLastValid, transactionFee, scLeaseBytes(cmd), keyDilution, walletName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: %s\n", err)
			}
		})
	},
}

func renewPartKeysInDir(dataDir string, lastValidRound basics.Round, fee uint64, leaseBytes [32]byte, dilution uint64, wallet string) error {
	client := ensureAlgodClient(dataDir)

	// Build list of accounts to renew from all accounts with part keys present
	parts, err := client.ListParticipationKeys()
	if err != nil {
		return fmt.Errorf(errorRequestFail, err)
	}
	renewAccounts := make(map[string]model.ParticipationKey)
	for _, part := range parts {
		if existing, has := renewAccounts[part.Address]; has {
			if existing.Key.VoteFirstValid >= part.Key.VoteLastValid {
				// We already saw a partkey that expires later
				continue
			}
		}
		renewAccounts[part.Address] = part
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

	if lastValidRound <= (currentRound + basics.Round(proto.MaxTxnLife)) {
		return fmt.Errorf(errLastRoundInvalid, currentRound)
	}
	txLastValidRound := currentRound + basics.Round(proto.MaxTxnLife)

	var anyErrors bool

	// Now go through each account and if it doesn't have a part key that's valid
	// at least through lastValidRound, generate a new key and register it.
	// Make sure we don't already have a partkey valid for (or after) specified roundLastValid
	for _, renewPart := range renewAccounts {
		if renewPart.Key.VoteLastValid >= lastValidRound {
			fmt.Printf("  Skipping account %s: Already has a part key valid beyond %d (currently %d)\n", renewPart.Address, lastValidRound, renewPart.Key.VoteLastValid)
			continue
		}

		// If the account's latest partkey expired before the current round, don't automatically renew and instead instruct the user to explicitly renew it.
		if renewPart.Key.VoteLastValid < lastValidRound {
			fmt.Printf("  Skipping account %s: This account has part keys that have expired.  Please renew this account explicitly using 'renewpartkey'\n", renewPart.Address)
			continue
		}

		address := renewPart.Address
		err = generateAndRegisterPartKey(address, currentRound, lastValidRound, txLastValidRound, fee, leaseBytes, dilution, wallet, dataDir, client)
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

func maxRound(current basics.Round, next *basics.Round) basics.Round {
	if next != nil && *next > current {
		return *next
	}
	return current
}

var listParticipationKeysCmd = &cobra.Command{
	Use:   "listpartkeys",
	Short: "List participation keys summary",
	Long:  `List all participation keys tracked by algod along with summary of additional information. For detailed key information use 'partkeyinfo'.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()

		client := ensureGoalClient(dataDir, libgoal.DynamicClient)
		parts, err := client.ListParticipationKeys()
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		// Squeezed this into 77 characters.
		hdrFormat := "%-10s  %-11s  %-15s  %10s  %11s  %10s\n"
		rowFormat := "%-10s  %-11s  %-15s  %10s  %11d  %10d\n"
		fmt.Printf(hdrFormat, "Registered", "Account", "ParticipationID", "Last Used", "First round", "Last round")
		for _, part := range parts {
			onlineAccountInfo, err := client.AccountInformation(part.Address, false)
			if err == nil {
				onlineInfoStr := "no"
				votingBytes := part.Key.VoteParticipationKey
				vrfBytes := part.Key.SelectionParticipationKey
				if onlineAccountInfo.Participation != nil &&
					(string(onlineAccountInfo.Participation.VoteParticipationKey) == string(votingBytes[:])) &&
					(string(onlineAccountInfo.Participation.SelectionParticipationKey) == string(vrfBytes[:])) &&
					(onlineAccountInfo.Participation.VoteFirstValid == part.Key.VoteFirstValid) &&
					(onlineAccountInfo.Participation.VoteLastValid == part.Key.VoteLastValid) &&
					(onlineAccountInfo.Participation.VoteKeyDilution == part.Key.VoteKeyDilution) {
					onlineInfoStr = "yes"
				}

				/*
					// PKI TODO: We could avoid querying the account with something like this.
					//       One problem is that it doesn't account for multiple keys on the same
					//       account, so we'd still need to query the round.
					if part.EffectiveFirstValid != nil && part.EffectiveLastValid < currentRound {
						onlineInfoStr = "yes"
					} else {
						onlineInfoStr = "no"
					}
				*/

				// it's okay to proceed without algod info
				lastUsed := maxRound(0, part.LastVote)
				lastUsed = maxRound(lastUsed, part.LastBlockProposal)
				lastUsed = maxRound(lastUsed, part.LastStateProof)
				lastUsedString := roundOrNA(&lastUsed)
				fmt.Printf(rowFormat,
					onlineInfoStr,
					fmt.Sprintf("%s...%s", part.Address[:4], part.Address[len(part.Address)-4:]),
					fmt.Sprintf("%s...", part.Id[:8]),
					lastUsedString,
					part.Key.VoteFirstValid,
					part.Key.VoteLastValid)
			}
		}
	},
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an account key from mnemonic",
	Long:  "Import an account key from a mnemonic generated by the export command or by algokey (NOT a mnemonic from the goal wallet command). The imported account will be listed alongside your wallet-generated accounts, but will not be tied to your wallet.",
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()
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
		dataDir := datadir.EnsureSingleDataDir()
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
		dataDir := datadir.EnsureSingleDataDir()
		// Generate a participation keys database and install it
		client := ensureKmdClient(dataDir)

		genID, err := client.GenesisID()
		if err != nil {
			return
		}

		keyDir := filepath.Join(dataDir, genID)
		files, err := os.ReadDir(keyDir)
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
				continue
			}

			// Fetch an account.Participation from the database
			root, err := algodAcct.RestoreRoot(handle)
			handle.Close()
			if err != nil {
				// Couldn't read it, skip it
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

func roundOrNA(value *basics.Round) string {
	if value == nil || *value == 0 {
		return "N/A"
	}
	return strconv.FormatUint(uint64(*value), 10)
}

var partkeyInfoCmd = &cobra.Command{
	Use:   "partkeyinfo",
	Short: "Output details about all available part keys",
	Long:  `Output details about all available part keys in the specified data directory(ies), such as key validity period.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		datadir.OnDataDirs(func(dataDir string) {
			fmt.Printf("Dumping participation key info from %s...\n", dataDir)
			client := ensureAlgodClient(dataDir)

			// Make sure we don't already have a partkey valid for (or after) specified roundLastValid
			parts, err := client.ListParticipationKeys()
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			for _, part := range parts {
				fmt.Println()
				fmt.Printf("Participation ID:          %s\n", part.Id)
				fmt.Printf("Parent address:            %s\n", part.Address)
				fmt.Printf("Last vote round:           %s\n", roundOrNA(part.LastVote))
				fmt.Printf("Last block proposal round: %s\n", roundOrNA(part.LastBlockProposal))
				// PKI TODO: enable with state proof support.
				//fmt.Printf("Last state proof round:    %s\n", strOrNA(part.LastStateProof))
				fmt.Printf("Effective first round:     %s\n", roundOrNA(part.EffectiveFirstValid))
				fmt.Printf("Effective last round:      %s\n", roundOrNA(part.EffectiveLastValid))
				fmt.Printf("First round:               %d\n", part.Key.VoteFirstValid)
				fmt.Printf("Last round:                %d\n", part.Key.VoteLastValid)
				fmt.Printf("Key dilution:              %d\n", part.Key.VoteKeyDilution)
				fmt.Printf("Selection key:             %s\n", base64.StdEncoding.EncodeToString(part.Key.SelectionParticipationKey))
				fmt.Printf("Voting key:                %s\n", base64.StdEncoding.EncodeToString(part.Key.VoteParticipationKey))
				if part.Key.StateProofKey != nil {
					fmt.Printf("State proof key:           %s\n", base64.StdEncoding.EncodeToString(*part.Key.StateProofKey))
				}
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

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		firstTxRound, lastTxRound, _, err := client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
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
		signedTxn, err := client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, utx)
		if err != nil {
			reportErrorf(errorSigningTX, err)
		}

		txid, err := client.BroadcastTransaction(signedTxn)
		if err != nil {
			reportErrorf(errorBroadcastingTX, err)
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
