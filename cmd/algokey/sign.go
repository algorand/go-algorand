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
	"io"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var signKeyfile string
var signTxfile string
var signOutfile string
var signMnemonic string

func init() {
	signCmd.Flags().StringVarP(&signKeyfile, "keyfile", "k", "", "Private key filename")
	signCmd.Flags().StringVarP(&signMnemonic, "mnemonic", "m", "", "Private key mnemonic")
	signCmd.Flags().StringVarP(&signTxfile, "txfile", "t", "", "Transaction input filename")
	signCmd.MarkFlagRequired("txfile")
	signCmd.Flags().StringVarP(&signOutfile, "outfile", "o", "", "Transaction output filename")
	signCmd.MarkFlagRequired("outfile")
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign transactions from a file using a private key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		seed := loadKeyfileOrMnemonic(signKeyfile, signMnemonic)
		key := crypto.GenerateSignatureSecrets(seed)

		txdata, err := ioutil.ReadFile(signTxfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read transactions from %s: %v\n", signTxfile, err)
			os.Exit(1)
		}

		var outBytes []byte
		dec := protocol.NewDecoderBytes(txdata)
		for {
			var stxn transactions.SignedTxn
			err = dec.Decode(&stxn)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot decode transaction: %v\n", err)
				os.Exit(1)
			}

			stxn.Sig = key.Sign(stxn.Txn)
			if stxn.Txn.Sender != basics.Address(key.SignatureVerifier) {
				stxn.AuthAddr = basics.Address(key.SignatureVerifier)
			}
			outBytes = append(outBytes, protocol.Encode(&stxn)...)
		}

		err = ioutil.WriteFile(signOutfile, outBytes, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write signed transactions to %s: %v\n", signOutfile, err)
			os.Exit(1)
		}
	},
}
