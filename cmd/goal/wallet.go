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
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
)

var (
	recoverWallet           bool
	createUnencryptedWallet bool
	noDisplaySeed           bool
	defaultWalletName       string
)

func init() {
	walletCmd.AddCommand(newWalletCmd)
	walletCmd.AddCommand(listWalletsCmd)
	walletCmd.AddCommand(renameWalletCmd)

	// Default wallet to use when -w not specified
	walletCmd.Flags().StringVarP(&defaultWalletName, "default", "f", "", "Set the wallet with this name to be the default wallet")

	// Should we recover the wallet?
	newWalletCmd.Flags().BoolVarP(&recoverWallet, "recover", "r", false, "Recover the wallet from the backup mnemonic provided at wallet creation (NOT the mnemonic provided by goal account export or by algokey). Regenerate accounts in the wallet with `goal account new`")
	newWalletCmd.Flags().BoolVar(&createUnencryptedWallet, "unencrypted", false, "Create a new wallet without a password.")
	newWalletCmd.Flags().BoolVar(&noDisplaySeed, "no-display-seed", false, "Create a new wallet without displaying the seed phrase.")
}

var walletCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Manage wallets: encrypted collections of Algorand account keys",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// Update the default wallet
		if defaultWalletName != "" {
			dataDir := datadir.EnsureSingleDataDir()
			accountList := makeAccountsList(dataDir)

			// Check that the new default wallet exists and isn't a duplicate
			client := ensureKmdClient(dataDir)
			wid, dup, err := client.FindWalletIDByName([]byte(defaultWalletName))
			if err != nil {
				reportErrorf(errFindingWallet, defaultWalletName)
			}
			if dup {
				reportErrorf(errWalletNameAmbiguous, defaultWalletName)
			}
			if len(wid) == 0 {
				reportErrorf(errWalletNotFound, defaultWalletName)
			}
			// Set this wallet to be the default
			accountList.setDefaultWalletID(wid)
			reportInfof(infoSetWalletToDefault, defaultWalletName)
			os.Exit(0)
		}
		cmd.HelpFunc()(cmd, args)
	},
}

var newWalletCmd = &cobra.Command{
	Use:   "new [wallet name]",
	Short: "Create a new wallet",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		dataDir := datadir.EnsureSingleDataDir()
		accountList := makeAccountsList(dataDir)
		client := ensureKmdClient(dataDir)
		walletName := []byte(args[0])

		reader := bufio.NewReader(os.Stdin)

		// Check if we should recover the wallet from a mnemonic
		var mdk crypto.MasterDerivationKey
		if recoverWallet {
			fmt.Println(infoRecoveryPrompt)
			resp, err1 := reader.ReadString('\n')
			resp = strings.TrimSpace(resp)
			if err1 != nil {
				reportErrorf(errorFailedToReadResponse, err1)
			}
			var key []byte
			key, err1 = passphrase.MnemonicToKey(resp)
			if err1 != nil {
				reportErrorf(errorBadMnemonic, err1)
			}
			// Copy the recovered key into the mdk
			n := copy(mdk[:], key)
			if n != len(mdk) {
				reportErrorln(errorBadRecoveredKey)
			}
		}

		walletPassword := []byte{}

		if createUnencryptedWallet {
			reportInfoln(infoUnencrypted)
		} else {
			// Fetch a password for the wallet
			fmt.Printf(infoChoosePasswordPrompt, walletName)
			walletPassword = ensurePassword()

			// Confirm the password
			fmt.Print(infoPasswordConfirmation)
			passwordConfirmation := ensurePassword()

			// Check the password confirmation
			if !bytes.Equal(walletPassword, passwordConfirmation) {
				reportErrorln(errorPasswordConfirmation)
			}
		}

		// Create the wallet
		reportInfoln(infoCreatingWallet)
		walletID, err := client.CreateWallet(walletName, walletPassword, mdk)
		if err != nil {
			reportErrorf(errorCouldntCreateWallet, err)
		}
		reportInfof(infoCreatedWallet, walletName)

		if !recoverWallet && !noDisplaySeed {
			// Offer to print backup seed
			fmt.Println(infoBackupExplanation)
			resp, err1 := reader.ReadString('\n')
			resp = strings.TrimSpace(resp)
			if err1 != nil {
				reportErrorf(errorFailedToReadResponse, err1)
			}

			if strings.ToLower(resp) != "n" {
				// Get a wallet handle token
				token, err1 := client.GetWalletHandleToken(walletID, walletPassword)
				if err1 != nil {
					reportErrorf(errorCouldntInitializeWallet, err1)
				}

				// Invalidate the handle when we're done with it
				defer client.ReleaseWalletHandle(token)

				// Export the master derivation key
				mdk, err1 := client.ExportMasterDerivationKey(token, walletPassword)
				if err1 != nil {
					reportErrorf(errorCouldntExportMDK, err1)
				}

				// Convert the key to a mnemonic
				mnemonic, err1 := passphrase.KeyToMnemonic(mdk[:])
				if err1 != nil {
					reportErrorf(errorCouldntMakeMnemonic, err1)
				}

				// Display the mnemonic to the user
				reportInfoln(infoPrintedBackupPhrase)
				reportInfof(infoBackupPhrase, mnemonic)
			}
		}

		// Check if we're the only wallet
		wallets, err := client.ListWallets()
		if err != nil {
			reportErrorf(errorCouldntListWallets, err)
		}

		// We are the only wallet -- make us the default
		if len(wallets) == 1 {
			accountList.setDefaultWalletID(walletID)
		}
	},
}

var listWalletsCmd = &cobra.Command{
	Use:   "list",
	Short: "List wallets managed by kmd",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		datadir.OnDataDirs(func(dataDir string) {
			client := ensureKmdClient(dataDir)
			wallets, err := client.ListWallets()
			if err != nil {
				reportErrorf(errorCouldntListWallets, err)
			}
			printWallets(dataDir, wallets)
		})
	},
}

var renameWalletCmd = &cobra.Command{
	Use:   "rename [wallet name] [new wallet name]",
	Short: "Rename wallet",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()

		client := ensureKmdClient(dataDir)

		walletName := []byte(args[0])
		newWalletName := []byte(args[1])

		if bytes.Equal(walletName, newWalletName) {
			reportErrorf(errorCouldntRenameWallet, "new name is identical to current name")
		}

		wid, duplicate, err := client.FindWalletIDByName(walletName)

		if err != nil {
			reportErrorf(errorCouldntRenameWallet, err)
		}

		if wid == nil {
			reportErrorf(errorCouldntFindWallet, string(walletName))
		}

		if duplicate {
			reportErrorf(errorCouldntRenameWallet, "Multiple wallets by the same name are not supported")
		}

		walletPassword := []byte{}

		// if wallet is encrypted, fetch the password
		if !client.WalletIsUnencrypted(wid) {
			fmt.Printf(infoPasswordPrompt, walletName)
			walletPassword = ensurePassword()
		}

		err = client.RenameWallet(wid, newWalletName, walletPassword)
		if err != nil {
			reportErrorf(errorCouldntRenameWallet, err)
		}

		reportInfof(infoRenamedWallet, walletName, newWalletName)
	},
}

func printWallets(dataDir string, wallets []kmdapi.APIV1Wallet) {
	accountList := makeAccountsList(dataDir)
	defaultWalletID := string(accountList.getDefaultWalletID())
	if len(wallets) == 0 {
		reportInfoln(infoNoWallets)
		return
	}
	for _, w := range wallets {
		// Append an indicator to the wallet name if it's the default
		var defaultIndicator string
		if w.ID == defaultWalletID {
			defaultIndicator = " (default)"
		}

		// Print the wallet information
		fmt.Println(strings.Repeat("#", 50))
		fmt.Printf("Wallet:\t%s%s\n", w.Name, defaultIndicator)
		fmt.Printf("ID:\t%s\n", w.ID)
	}
	fmt.Println(strings.Repeat("#", 50))
}
