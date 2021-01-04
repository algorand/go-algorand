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
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var multisigKeyfile string
var multisigTxfile string
var multisigOutfile string
var multisigMnemonic string

var msigParams string

func init() {

	multisigCmd.AddCommand(appendAuthAddrCmd)

	multisigCmd.Flags().StringVarP(&multisigKeyfile, "keyfile", "k", "", "Private key filename")
	multisigCmd.Flags().StringVarP(&multisigMnemonic, "mnemonic", "m", "", "Private key mnemonic")
	multisigCmd.Flags().StringVarP(&multisigTxfile, "txfile", "t", "", "Transaction input filename")
	multisigCmd.MarkFlagRequired("txfile")
	multisigCmd.Flags().StringVarP(&multisigOutfile, "outfile", "o", "", "Transaction output filename")
	multisigCmd.MarkFlagRequired("outfile")

	appendAuthAddrCmd.Flags().StringVarP(&msigParams, "params", "p", "", "Multisig pre image parameters - [threshold] [Address 1] [Address 2] ...")
	appendAuthAddrCmd.MarkFlagRequired("params")
	appendAuthAddrCmd.Flags().StringVarP(&multisigTxfile, "txfile", "t", "", "Transaction input filename")
	appendAuthAddrCmd.MarkFlagRequired("txfile")
	appendAuthAddrCmd.Flags().StringVarP(&multisigOutfile, "outfile", "o", "", "Transaction output filename. If not specified, the original file will be modified")

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

			outBytes = append(outBytes, protocol.Encode(&stxn)...)
		}

		err = ioutil.WriteFile(multisigOutfile, outBytes, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write signed transactions to %s: %v\n", multisigOutfile, err)
			os.Exit(1)
		}
	},
}

var appendAuthAddrCmd = &cobra.Command{
	Use:   "append-auth-addr -t [transaction file] -p \"[threshold] [Address 1] [Address 2] ...\"",
	Short: "Adds the necessary fields to a transaction that is sent from an account that was rekeyed to a multisig account",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {

		// Read Transaction
		txdata, err := readFile(multisigTxfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read transactions from %s: %v\n", multisigTxfile, err)
			os.Exit(1)
		}

		var outBytes []byte
		dec := protocol.NewDecoderBytes(txdata)

		var stxn transactions.SignedTxn
		err = dec.Decode(&stxn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot decode transaction: %v\n", err)
			os.Exit(1)
		}

		// Decode params
		params := strings.Split(msigParams, " ")
		if len(params) < 3 {
			fmt.Fprint(os.Stderr, "Not enough arguments to create the multisig address.\nPlease make sure to specify the threshold and at least 2 addresses\n")
			os.Exit(1)
		}

		threshold, err := strconv.ParseUint(params[0], 10, 8)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse the threshold. Make sure it's a number between 1 and 255: %v\n", err)
			os.Exit(1)
		}

		// Convert the addresses into public keys
		pks := make([]crypto.PublicKey, len(params[1:]))
		for i, addrStr := range params[1:] {
			addr, err := basics.UnmarshalChecksumAddress(addrStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot decode address: %v\n", err)
				os.Exit(1)
			}
			pks[i] = crypto.PublicKey(addr)
		}

		addr, err := crypto.MultisigAddrGen(1, uint8(threshold), pks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot generate multisig addr: %v\n", err)
			os.Exit(1)
		}

		// Generate the multisig and assign to the txn
		stxn.Msig = crypto.MultisigPreimageFromPKs(1, uint8(threshold), pks)

		// Append the signer since it's a rekey txn
		if basics.Address(addr) == stxn.Txn.Sender {
			fmt.Fprintf(os.Stderr, "The sender at the msig address should not be the same: %v\n", err)
			os.Exit(1)
		}
		stxn.AuthAddr = basics.Address(addr)

		// Write the txn
		outBytes = append(outBytes, protocol.Encode(&stxn)...)

		// Check if we should override the current file or create a new one
		if multisigOutfile == "" {
			multisigOutfile = multisigTxfile
		}

		err = writeFile(multisigOutfile, outBytes, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write transactions to %s: %v\n", multisigOutfile, err)
			os.Exit(1)
		}
	},
}
