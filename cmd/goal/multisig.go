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
	"io"
	"io/ioutil"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
)

var (
	addr string
)

func init() {
	clerkCmd.AddCommand(multisigCmd)
	multisigCmd.AddCommand(addSigCmd)
	multisigCmd.AddCommand(mergeSigCmd)

	addSigCmd.Flags().StringVarP(&txFilename, "tx", "t", "", "Partially-signed transaction file to add signature to")
	addSigCmd.Flags().StringVarP(&addr, "address", "a", "", "Address of the key to sign with")
	addSigCmd.MarkFlagRequired("tx")
	addSigCmd.MarkFlagRequired("address")

	mergeSigCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Output file for merged transactions")
	mergeSigCmd.MarkFlagRequired("out")
}

var multisigCmd = &cobra.Command{
	Use:   "multisig",
	Short: "Provides tools working with multisig transactions ",
	Long:  `Create, examine, and add signatures to multisig transactions`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var addSigCmd = &cobra.Command{
	Use:   "sign -t TXFILE -a ADDR",
	Short: "Add a signature to a multisig transaction",
	Long:  `Start a multisig, or add a signature to an existing multisig, for a given transaction`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
		}

		dataDir := ensureSingleDataDir()
		client := ensureKmdClient(dataDir)
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)

		var outData []byte
		dec := protocol.NewDecoderBytes(data)
		for {
			var stxn transactions.SignedTxn
			err = dec.Decode(&stxn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}

			msig, err := client.MultisigSignTransactionWithWallet(wh, pw, stxn.Txn, addr, stxn.Msig)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			// The following line makes stxn.cachedEncodingLen incorrect, but it's okay because we're just serializing it to a file
			stxn.Msig = msig

			outData = append(outData, protocol.Encode(stxn)...)
		}

		err = writeFile(txFilename, outData, 0600)
		if err != nil {
			reportErrorf(fileWriteError, txFilename, err)
		}
	},
}

var mergeSigCmd = &cobra.Command{
	Use:   "merge -o MERGEDTXFILE TXFILE1 TXFILE2 ...",
	Short: "Merge multisig signatures on transactions",
	Long:  `Combine multiple partially-signed multisig transactions, and write out transactions with a single merged multisig signature`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			reportErrorf(txNoFilesError)
		}

		var txnLists [][]transactions.SignedTxn
		for _, arg := range args {
			data, err := ioutil.ReadFile(arg)
			if err != nil {
				reportErrorf(fileReadError, arg, err)
			}

			dec := protocol.NewDecoderBytes(data)
			var txns []transactions.SignedTxn
			for {
				var txn transactions.SignedTxn
				err = dec.Decode(&txn)
				if err == io.EOF {
					break
				}
				if err != nil {
					reportErrorf(txDecodeError, arg, err)
				}
				txns = append(txns, txn)
			}

			txnLists = append(txnLists, txns)
		}

		// Ensure that all lists are the same length
		for _, txnList := range txnLists {
			if len(txnList) != len(txnLists[0]) {
				reportErrorf(txLengthError)
			}
		}

		// Merge multisigs
		var mergedTxns []transactions.SignedTxn
		for i, tx0 := range txnLists[0] {
			// Merge tx0 with every other i'th transaction, and check for txn equality
			for _, txnList := range txnLists {
				if tx0.ID() != txnList[i].ID() {
					reportErrorf(txMergeMismatch)
				}

				var err error
				tx0.Msig, err = crypto.MultisigMerge(tx0.Msig, txnList[i].Msig)
				if err != nil {
					reportErrorf(txMergeError, err)
				}
			}

			mergedTxns = append(mergedTxns, tx0)
		}

		// Write out the transactions to the output file
		var mergedData []byte
		for _, txn := range mergedTxns {
			mergedData = append(mergedData, protocol.Encode(txn)...)
		}

		err := writeFile(txFilename, mergedData, 0600)
		if err != nil {
			reportErrorf(fileWriteError, txFilename, err)
		}
	},
}

func populateBlankMultisig(client libgoal.Client, dataDir string, walletName string, stxn transactions.SignedTxn) transactions.SignedTxn {
	// Check if we have a multisig account, and if so, populate with
	// a blank multisig.  This allows `algokey multisig` to work.
	wh, _, err := getWalletHandleMaybePassword(dataDir, walletName, false)
	if err != nil {
		return stxn
	}

	multisigInfo, err := client.LookupMultisigAccount(wh, stxn.Txn.Sender.String())
	if err != nil {
		return stxn
	}

	var pks []crypto.PublicKey
	for _, pk := range multisigInfo.PKs {
		addr, err := basics.UnmarshalChecksumAddress(pk)
		if err != nil {
			return stxn
		}
		pks = append(pks, crypto.PublicKey(addr))
	}
	stxn.Msig = crypto.MultisigPreimageFromPKs(multisigInfo.Version, multisigInfo.Threshold, pks)
	return stxn
}
