// Copyright (C) 2019 Algorand, Inc.
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
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var multisigKeyfile string
var multisigTxfile string
var multisigOutfile string
var multisigMnemonic string

func init() {
	multisigCmd.Flags().StringVarP(&multisigKeyfile, "keyfile", "k", "", "Private key filename")
	multisigCmd.Flags().StringVarP(&multisigMnemonic, "mnemonic", "m", "", "Private key mnemonic")
	multisigCmd.Flags().StringVarP(&multisigTxfile, "txfile", "t", "", "Transaction input filename")
	multisigCmd.MarkFlagRequired("txfile")
	multisigCmd.Flags().StringVarP(&multisigOutfile, "outfile", "o", "", "Transaction output filename")
	multisigCmd.MarkFlagRequired("outfile")
}

var multisigCmd = &cobra.Command{
	Use:   "multisig",
	Short: "Add a multisig signature to transactions from a file using a private key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		seed := loadKeyfileOrMnemonic(multisigKeyfile, multisigMnemonic)
		key := crypto.GenerateSignatureSecrets(seed)

		txdata, err := ioutil.ReadFile(multisigTxfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read transactions from %s: %v\n", multisigTxfile, err)
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

			ver, thresh, pks := stxn.Msig.Preimage()
			addr, err := crypto.MultisigAddrGen(ver, thresh, pks)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot generate multisig addr: %v\n", err)
				os.Exit(1)
			}

			stxn.Msig, err = crypto.MultisigSign(stxn.Txn, addr, ver, thresh, pks, *key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot add multisig signature: %v\n", err)
				os.Exit(1)
			}

			outBytes = append(outBytes, protocol.Encode(stxn)...)
		}

		err = ioutil.WriteFile(multisigOutfile, outBytes, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write signed transactions to %s: %v\n", multisigOutfile, err)
			os.Exit(1)
		}
	},
}
