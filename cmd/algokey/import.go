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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

var mnemonic string
var importKeyfile string

func init() {
	importCmd.Flags().StringVarP(&mnemonic, "mnemonic", "m", "", "Private key mnemonic")
	importCmd.Flags().StringVarP(&importKeyfile, "keyfile", "f", "", "Private key filename")
	importCmd.MarkFlagRequired("mnemonic")
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import key file from mnemonic",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		seed := loadMnemonic(mnemonic)

		key := crypto.GenerateSignatureSecrets(seed)
		publicKeyChecksummed := basics.Address(key.SignatureVerifier).String()

		fmt.Printf("Private key mnemonic: %s\n", mnemonic)
		fmt.Printf("Public key: %s\n", publicKeyChecksummed)

		if importKeyfile != "" {
			writePrivateKey(importKeyfile, seed)
		}
	},
}
