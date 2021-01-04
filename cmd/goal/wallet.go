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
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
)

var (
	recoverWallet     bool
	defaultWalletName string
)

func init() {
	walletCmd.AddCommand(newWalletCmd)
	walletCmd.AddCommand(listWalletsCmd)

	// Default wallet to use when -w not specified
	walletCmd.Flags().StringVarP(&defaultWalletName, "default", "f", "", "Set the wallet with this name to be the default wallet")

	// Should we recover the wallet?
	newWalletCmd.Flags().BoolVarP(&recoverWallet, "recover", "r", false, "Recover the wallet from the backup mnemonic provided at wallet creation (NOT the mnemonic provided by goal account export or by algokey). Regenerate accounts in the wallet with `goal account new`")
}

var walletCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Manage wallets: encrypted collections of Algorand account keys",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// Update the default wallet
		if defaultWalletName != "" {
			dataDir := ensureSingleDataDir()
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

		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)
		client := ensureKmdClient(dataDir)
		walletName := []byte(args[0])

		reader := bufio.NewReader(os.Stdin)

		// Check if we should recover the wallet from a mnemonic
		var mdk crypto.MasterDerivationKey
		if recoverWallet {
			fmt.Println(infoRecoveryPrompt)
			resp, err := reader.ReadString('\n')
			resp = strings.TrimSpace(resp)
			if err != nil {
				reportErrorf(errorFailedToReadResponse, err)
			}
			var key []byte
			key, err = passphrase.MnemonicToKey(resp)
			if err != nil {
				reportErrorf(errorBadMnemonic, err)
			}
			// Copy the recovered key into the mdk
			n := copy(mdk[:], key)
			if n != len(mdk) {
				reportErrorln(errorBadRecoveredKey)
			}
		}

		// Fetch a password for the wallet
		fmt.Printf(infoChoosePasswordPrompt, walletName)
		walletPassword := ensurePassword()

		// Confirm the password
		fmt.Printf(infoPasswordConfirmation)
		passwordConfirmation := ensurePassword()

		// Check the password confirmation
		if !bytes.Equal(walletPassword, passwordConfirmation) {
			reportErrorln(errorPasswordConfirmation)
		}

		// Create the wallet
		reportInfoln(infoCreatingWallet)
		walletID, err := client.CreateWallet(walletName, walletPassword, mdk)
		if err != nil {
			reportErrorf(errorCouldntCreateWallet, err)
		}
		reportInfof(infoCreatedWallet, walletName)

		if !recoverWallet {
			// Offer to print backup seed
			fmt.Printf(infoBackupExplanation)
			resp, err := reader.ReadString('\n')
			resp = strings.TrimSpace(resp)
			if err != nil {
				reportErrorf(errorFailedToReadResponse, err)
			}

			if strings.ToLower(resp) != "n" {
				// Get a wallet handle token
				token, err := client.GetWalletHandleToken(walletID, walletPassword)
				if err != nil {
					reportErrorf(errorCouldntInitializeWallet, err)
				}

				// Invalidate the handle when we're done with it
				defer client.ReleaseWalletHandle(token)

				// Export the master derivation key
				mdk, err := client.ExportMasterDerivationKey(token, walletPassword)
				if err != nil {
					reportErrorf(errorCouldntExportMDK, err)
				}

				// Convert the key to a mnemonic
				mnemonic, err := passphrase.KeyToMnemonic(mdk[:])
				if err != nil {
					reportErrorf(errorCouldntMakeMnemonic, err)
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
		onDataDirs(func(dataDir string) {
			client := ensureKmdClient(dataDir)
			wallets, err := client.ListWallets()
			if err != nil {
				reportErrorf(errorCouldntListWallets, err)
			}
			printWallets(dataDir, wallets)
		})
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
