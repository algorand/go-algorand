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
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"

	"github.com/spf13/cobra"
)

var (
	toAddress       string
	account         string
	amount          uint64
	fee             uint64
	firstValid      uint64
	lastValid       uint64
	txFilename      string
	outFilename     string
	rejectsFilename string
	noteBase64      string
	noteText        string
	sign            bool
	closeToAddress  string
	noWaitAfterSend bool
)

func init() {
	clerkCmd.AddCommand(sendCmd)
	clerkCmd.AddCommand(rawsendCmd)
	clerkCmd.AddCommand(inspectCmd)
	clerkCmd.AddCommand(signCmd)

	// Wallet to be used for the clerk operation
	clerkCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")

	// send flags
	sendCmd.Flags().StringVarP(&account, "from", "f", "", "Account address to send the money from (If not specified, uses default account)")
	sendCmd.Flags().StringVarP(&toAddress, "to", "t", "", "Address to send to money to (required)")
	sendCmd.Flags().Uint64VarP(&amount, "amount", "a", 0, "The amount to be transferred (required), in microAlgos")
	sendCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	sendCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	sendCmd.Flags().Uint64Var(&lastValid, "lastvalid", 0, "The last round where the transaction may be committed to the ledger")
	sendCmd.Flags().StringVar(&noteBase64, "noteb64", "", "Note (URL-base64 encoded)")
	sendCmd.Flags().StringVarP(&noteText, "note", "n", "", "Note text (ignored if --noteb64 used also)")
	sendCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Dump an unsigned tx to the given file. In order to dump a signed transaction, pass -s")
	sendCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	sendCmd.Flags().StringVarP(&closeToAddress, "close-to", "c", "", "Close account and send remainder to this address")
	sendCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")

	sendCmd.MarkFlagRequired("to")
	sendCmd.MarkFlagRequired("amount")

	// rawsend flags
	rawsendCmd.Flags().StringVarP(&txFilename, "filename", "f", "", "Filename of file containing raw transactions")
	rawsendCmd.Flags().StringVarP(&rejectsFilename, "rejects", "r", "", "Filename for writing rejects to (default is txFilename.rej)")
	rawsendCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transactions to commit")
	rawsendCmd.MarkFlagRequired("filename")

	signCmd.Flags().StringVarP(&txFilename, "infile", "i", "", "Partially-signed transaction file to add signature to")
	signCmd.Flags().StringVarP(&outFilename, "outfile", "o", "", "Filename for writing the signed transaction")
	signCmd.MarkFlagRequired("infile")
	signCmd.MarkFlagRequired("outfile")
}

var clerkCmd = &cobra.Command{
	Use:   "clerk",
	Short: "Provides the tools to control transactions ",
	Long:  `Collection of commands to support the mangement of transaction information.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

func waitForCommit(client libgoal.Client, txid string) error {
	// Get current round information
	stat, err := client.Status()
	if err != nil {
		return fmt.Errorf(errorRequestFail, err)
	}

	for {
		// Check if we know about the transaction yet
		txn, err := client.PendingTransactionInformation(txid)
		if err != nil {
			return fmt.Errorf(errorRequestFail, err)
		}

		if txn.ConfirmedRound > 0 {
			reportInfof(infoTxCommitted, txid, txn.ConfirmedRound)
			break
		}

		if txn.PoolError != "" {
			return fmt.Errorf(txPoolError, txid, txn.PoolError)
		}

		reportInfof(infoTxPending, txid, stat.LastRound)
		stat, err = client.WaitForRound(stat.LastRound + 1)
		if err != nil {
			return fmt.Errorf(errorRequestFail, err)
		}
	}

	return nil
}

func writeTxnToFile(client libgoal.Client, signTx bool, dataDir string, walletName string, tx transactions.Transaction, filename string) error {
	var err error
	var stxn transactions.SignedTxn
	if signTx {
		// Sign the transaction
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
		stxn, err = client.SignTransactionWithWallet(wh, pw, tx)
		if err != nil {
			return err
		}
	} else {
		// Wrap in a transactions.SignedTxn with an empty sig.
		// This way protocol.Encode will encode the transaction type
		stxn, err = transactions.AssembleSignedTxn(tx, crypto.Signature{}, crypto.MultisigSig{})
		if err != nil {
			return err
		}

		stxn = populateBlankMultisig(client, dataDir, walletName, stxn)
	}

	// Write the SignedTxn to the output file
	return writeFile(filename, protocol.Encode(stxn), 0600)
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send money to an address",
	Long:  `Send money from one account to another. Note: by default, the money will be withdrawn from the default account. Creates a transaction sending amount tokens from fromAddr to toAddr. If the optional --fee is not provided, the transaction will use the recommended amount. If the optional --firstvalid and --lastvalid are provided, the transaction will only be valid from round firstValid to round lastValid. If broadcast of the transaction is successful, the transaction ID will be returned.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// -s is invalid without -o
		if txFilename == "" && sign {
			reportErrorln(soFlagError)
		}

		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)

		// Check if from was specified, else use default
		if account == "" {
			account = accountList.getDefaultAccount()
		}

		// Resolving friendly names
		fromAddressResolved := accountList.getAddressByName(account)
		toAddressResolved := accountList.getAddressByName(toAddress)

		// Parse notes field
		var noteBytes []byte
		var err error
		if cmd.Flags().Changed("noteb64") {
			noteBytes, err = base64.StdEncoding.DecodeString(noteBase64)
			if err != nil {
				reportErrorf(malformedNote, noteBase64, err)
			}
		} else if cmd.Flags().Changed("note") {
			noteBytes = []byte(noteText)
		} else {
			// Make sure that back-to-back, similar transactions will have a different txid
			noteBytes = make([]byte, 8)
			crypto.RandBytes(noteBytes[:])
		}

		// If closing an account, resolve that address as well
		var closeToAddressResolved string
		if closeToAddress != "" {
			closeToAddressResolved = accountList.getAddressByName(closeToAddress)
		}

		client := ensureFullClient(dataDir)
		if txFilename == "" {
			// Sign and broadcast the tx
			wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
			tx, err := client.SendPaymentFromWallet(wh, pw, fromAddressResolved, toAddressResolved, fee, amount, noteBytes, closeToAddressResolved, basics.Round(firstValid), basics.Round(lastValid))

			// update information from Transaction
			txid := tx.ID().String()
			fee = tx.Fee.Raw

			if err != nil {
				reportErrorf(errorBroadcastingTX, err)
			}

			// Report tx details to user
			reportInfof(infoTxIssued, amount, fromAddressResolved, toAddressResolved, txid, fee)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			payment, err := client.ConstructPayment(fromAddressResolved, toAddressResolved, fee, amount, noteBytes, closeToAddressResolved, basics.Round(firstValid), basics.Round(lastValid))
			if err != nil {
				reportErrorf(errorConstructingTX, err)
			}
			err = writeTxnToFile(client, sign, dataDir, walletName, payment, txFilename)
			if err != nil {
				reportErrorf(err.Error())
			}
		}
	},
}

var rawsendCmd = &cobra.Command{
	Use:   "rawsend",
	Short: "Send raw transactions",
	Long:  `Send raw transactions.  The transactions must be stored in a file, encoded using msgpack as transactions.SignedTxn. Multiple transactions can be concatenated together in a file.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if rejectsFilename == "" {
			rejectsFilename = txFilename + ".rej"
		}

		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
		}

		dec := protocol.NewDecoderBytes(data)
		client := ensureAlgodClient(ensureSingleDataDir())

		txns := make(map[transactions.Txid]transactions.SignedTxn)
		for {
			var txn transactions.SignedTxn
			err = dec.Decode(&txn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}

			_, present := txns[txn.ID()]
			if present {
				reportErrorf(txDupError, txn.ID().String(), txFilename)
			}

			txns[txn.ID()] = txn
		}

		txnErrors := make(map[transactions.Txid]string)
		pendingTxns := make(map[transactions.Txid]string)
		for txid, txn := range txns {
			// Broadcast the transaction
			txidStr, err := client.BroadcastTransaction(txn)
			if err != nil {
				txnErrors[txid] = err.Error()
				reportWarnf(errorBroadcastingTX, err)
				continue
			}

			reportInfof(infoRawTxIssued, txidStr)
			pendingTxns[txid] = txidStr
		}

		if noWaitAfterSend {
			return
		}

		// Get current round information
		stat, err := client.Status()
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		for txid, txidStr := range pendingTxns {
			for {
				// Check if we know about the transaction yet
				txn, err := client.PendingTransactionInformation(txidStr)
				if err != nil {
					txnErrors[txid] = err.Error()
					reportWarnf(errorRequestFail, err)
					continue
				}

				if txn.ConfirmedRound > 0 {
					reportInfof(infoTxCommitted, txidStr, txn.ConfirmedRound)
					break
				}

				if txn.PoolError != "" {
					txnErrors[txid] = txn.PoolError
					reportWarnf(txPoolError, txidStr, txn.PoolError)
					continue
				}

				reportInfof(infoTxPending, txidStr, stat.LastRound)
				stat, err = client.WaitForRound(stat.LastRound + 1)
				if err != nil {
					reportErrorf(errorRequestFail, err)
				}
			}
		}

		if len(txnErrors) > 0 {
			fmt.Printf("Encountered errors in sending %d transactions:\n", len(txnErrors))

			var rejectsData []byte
			for txid, errmsg := range txnErrors {
				fmt.Printf("  %s: %s\n", txid, errmsg)
				rejectsData = append(rejectsData, protocol.Encode(txns[txid])...)
			}

			f, err := os.OpenFile(rejectsFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
			if err != nil {
				reportErrorf(fileWriteError, rejectsFilename, err.Error())
			}
			_, err = f.Write(rejectsData)
			if err != nil {
				reportErrorf(fileWriteError, rejectsFilename, err.Error())
			}
			f.Close()
			fmt.Printf("Rejected transactions written to %s\n", rejectsFilename)

			os.Exit(1)
		}
	},
}

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "print a transaction file",
	Run: func(cmd *cobra.Command, args []string) {
		for _, txFilename := range args {
			data, err := readFile(txFilename)
			if err != nil {
				reportErrorf(fileReadError, txFilename, err)
			}

			dec := protocol.NewDecoderBytes(data)
			count := 0
			for {
				var txn transactions.SignedTxn
				err = dec.Decode(&txn)
				if err == io.EOF {
					break
				}
				if err != nil {
					reportErrorf(txDecodeError, txFilename, err)
				}
				sti, err := inspectTxn(txn)
				if err != nil {
					reportErrorf(txDecodeError, txFilename, err)
				}
				fmt.Printf("%s[%d]\n%s\n\n", txFilename, count, string(protocol.EncodeJSON(sti)))
				count++
			}
		}
	},
}

var signCmd = &cobra.Command{
	Use:   "sign -i INFILE -o OUTFILE",
	Short: "Sign a transaction file",
	Long:  `Sign the passed transaction file, which may contain one or more transactions. If the infile and the outfile are the same, this overwrites the file with the new, signed data.`,
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
			// transaction file comes in as a SignedTxn with no signature
			var unsignedTxn transactions.SignedTxn
			err = dec.Decode(&unsignedTxn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}

			signedTxn, err := client.SignTransactionWithWallet(wh, pw, unsignedTxn.Txn)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}

			outData = append(outData, protocol.Encode(signedTxn)...)
		}
		err = writeFile(outFilename, outData, 0600)
		if err != nil {
			reportErrorf(fileWriteError, outFilename, err)
		}
	},
}
