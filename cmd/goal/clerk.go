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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"

	"github.com/spf13/cobra"
)

var (
	toAddress       string
	account         string
	amount          uint64
	fee             uint64
	txFilename      string
	outFilename     string
	rejectsFilename string
	noteBase64      string
	noteText        string
	lease           string
	sign            bool
	closeToAddress  string
	noWaitAfterSend bool
	noProgramOutput bool
	signProgram     bool
	programSource   string
	argB64Strings   []string
	disassesmble    bool
	progByteFile    string
	logicSigFile    string
	timeStamp       int64
	protoVersion    string
)

func init() {
	clerkCmd.AddCommand(sendCmd)
	clerkCmd.AddCommand(rawsendCmd)
	clerkCmd.AddCommand(inspectCmd)
	clerkCmd.AddCommand(signCmd)
	clerkCmd.AddCommand(groupCmd)
	clerkCmd.AddCommand(splitCmd)
	clerkCmd.AddCommand(compileCmd)
	clerkCmd.AddCommand(dryrunCmd)

	// Wallet to be used for the clerk operation
	clerkCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")

	// send flags
	sendCmd.Flags().StringVarP(&account, "from", "f", "", "Account address to send the money from (If not specified, uses default account)")
	sendCmd.Flags().StringVarP(&toAddress, "to", "t", "", "Address to send to money to (required)")
	sendCmd.Flags().Uint64VarP(&amount, "amount", "a", 0, "The amount to be transferred (required), in microAlgos")
	sendCmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	sendCmd.Flags().Uint64Var(&firstValid, "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	sendCmd.Flags().Uint64Var(&lastValid, "lastvalid", 0, "The last round where the transaction may be committed to the ledger")
	sendCmd.Flags().Uint64VarP(&numValidRounds, "validrounds", "v", 0, "The validity period for the transaction, used to calculate lastvalid")
	sendCmd.Flags().StringVar(&noteBase64, "noteb64", "", "Note (URL-base64 encoded)")
	sendCmd.Flags().StringVarP(&noteText, "note", "n", "", "Note text (ignored if --noteb64 used also)")
	sendCmd.Flags().StringVarP(&lease, "lease", "x", "", "Lease value (base64, optional): no transaction may also acquire this lease until lastvalid")
	sendCmd.Flags().StringVarP(&txFilename, "out", "o", "", "Dump an unsigned tx to the given file. In order to dump a signed transaction, pass -s")
	sendCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	sendCmd.Flags().StringVarP(&closeToAddress, "close-to", "c", "", "Close account and send remainder to this address")
	sendCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	sendCmd.Flags().StringVarP(&programSource, "from-program", "F", "", "Program source to use as account logic")
	sendCmd.Flags().StringVarP(&progByteFile, "from-program-bytes", "P", "", "Program binary to use as account logic")
	sendCmd.Flags().StringSliceVar(&argB64Strings, "argb64", nil, "base64 encoded args to pass to transaction logic")
	sendCmd.Flags().StringVarP(&logicSigFile, "logic-sig", "L", "", "LogicSig to apply to transaction")

	sendCmd.MarkFlagRequired("to")
	sendCmd.MarkFlagRequired("amount")

	// rawsend flags
	rawsendCmd.Flags().StringVarP(&txFilename, "filename", "f", "", "Filename of file containing raw transactions")
	rawsendCmd.Flags().StringVarP(&rejectsFilename, "rejects", "r", "", "Filename for writing rejects to (default is txFilename.rej)")
	rawsendCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transactions to commit")
	rawsendCmd.MarkFlagRequired("filename")

	signCmd.Flags().StringVarP(&txFilename, "infile", "i", "", "Partially-signed transaction file to add signature to")
	signCmd.Flags().StringVarP(&outFilename, "outfile", "o", "", "Filename for writing the signed transaction")
	signCmd.Flags().StringVarP(&programSource, "program", "p", "", "Program source to use as account logic")
	signCmd.Flags().StringVarP(&logicSigFile, "logic-sig", "L", "", "LogicSig to apply to transaction")
	signCmd.Flags().StringSliceVar(&argB64Strings, "argb64", nil, "base64 encoded args to pass to transaction logic")
	signCmd.Flags().StringVarP(&protoVersion, "proto", "P", "", "consensus protocol version id string")
	signCmd.MarkFlagRequired("infile")
	signCmd.MarkFlagRequired("outfile")

	groupCmd.Flags().StringVarP(&txFilename, "infile", "i", "", "File storing transactions to be grouped")
	groupCmd.Flags().StringVarP(&outFilename, "outfile", "o", "", "Filename for writing the grouped transactions")
	groupCmd.MarkFlagRequired("infile")
	groupCmd.MarkFlagRequired("outfile")

	splitCmd.Flags().StringVarP(&txFilename, "infile", "i", "", "File storing transactions to be split")
	splitCmd.Flags().StringVarP(&outFilename, "outfile", "o", "", "Base filename for writing the individual transactions; each transaction will be written to filename-N.ext")
	splitCmd.MarkFlagRequired("infile")
	splitCmd.MarkFlagRequired("outfile")

	compileCmd.Flags().BoolVarP(&disassesmble, "disassemble", "D", false, "disassemble a compiled program")
	compileCmd.Flags().BoolVarP(&noProgramOutput, "no-out", "n", false, "don't write contract program binary")
	compileCmd.Flags().BoolVarP(&signProgram, "sign", "s", false, "sign program, output is a binary signed LogicSig record")
	compileCmd.Flags().StringVarP(&outFilename, "outfile", "o", "", "Filename to write program bytes or signed LogicSig to")
	compileCmd.Flags().StringVarP(&account, "account", "a", "", "Account address to sign the program (If not specified, uses default account)")

	dryrunCmd.Flags().StringVarP(&txFilename, "txfile", "t", "", "transaction or transaction-group to test")
	dryrunCmd.Flags().StringVarP(&protoVersion, "proto", "P", "", "consensus protocol version id string")
	dryrunCmd.MarkFlagRequired("txfile")
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

func createSignedTransaction(client libgoal.Client, signTx bool, dataDir string, walletName string, tx transactions.Transaction) (stxn transactions.SignedTxn, err error) {
	if signTx {
		// Sign the transaction
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
		stxn, err = client.SignTransactionWithWallet(wh, pw, tx)
		if err != nil {
			return
		}
	} else {
		// Wrap in a transactions.SignedTxn with an empty sig.
		// This way protocol.Encode will encode the transaction type
		stxn, err = transactions.AssembleSignedTxn(tx, crypto.Signature{}, crypto.MultisigSig{})
		if err != nil {
			return
		}

		stxn = populateBlankMultisig(client, dataDir, walletName, stxn)
	}
	return
}

func writeTxnToFile(client libgoal.Client, signTx bool, dataDir string, walletName string, tx transactions.Transaction, filename string) error {
	stxn, err := createSignedTransaction(client, signTx, dataDir, walletName, tx)
	if err != nil {
		return err
	}
	// Write the SignedTxn to the output file
	return writeFile(filename, protocol.Encode(stxn), 0600)
}

func getProgramArgs() [][]byte {
	if len(argB64Strings) == 0 {
		return nil
	}
	programArgs := make([][]byte, len(argB64Strings))
	for i, argstr := range argB64Strings {
		if argstr == "" {
			programArgs[i] = []byte{}
			continue
		}
		var err error
		programArgs[i], err = base64.StdEncoding.DecodeString(argstr)
		if err != nil {
			reportErrorf("arg[%d] decode error: %s", i, err)
		}
	}
	return programArgs
}

func parseNoteField(cmd *cobra.Command) []byte {
	if cmd.Flags().Changed("noteb64") {
		noteBytes, err := base64.StdEncoding.DecodeString(noteBase64)
		if err != nil {
			reportErrorf(malformedNote, noteBase64, err)
		}
		return noteBytes
	}

	if cmd.Flags().Changed("note") {
		return []byte(noteText)
	}

	// Make sure that back-to-back, similar transactions will have a different txid
	noteBytes := make([]byte, 8)
	crypto.RandBytes(noteBytes[:])
	return noteBytes
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

		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := ensureSingleDataDir()
		accountList := makeAccountsList(dataDir)

		var fromAddressResolved string
		var program []byte = nil
		var programArgs [][]byte = nil
		var lsig transactions.LogicSig
		var err error
		if progByteFile != "" {
			if programSource != "" || logicSigFile != "" {
				reportErrorln("should at most one of --from-program/-F or --from-program-bytes/-P --logic-sig/-L")
			}
			program, err = readFile(progByteFile)
			if err != nil {
				reportErrorf("%s: %s", progByteFile, err)
			}
		} else if programSource != "" {
			if logicSigFile != "" {
				reportErrorln("should at most one of --from-program/-F or --from-program-bytes/-P --logic-sig/-L")
			}
			program = assembleFile(programSource)
		} else if logicSigFile != "" {
			lsigFromArgs(&lsig)
		}
		if program != nil {
			ph := logic.HashProgram(program)
			pha := basics.Address(ph)
			fromAddressResolved = pha.String()
			programArgs = getProgramArgs()
		} else {
			// Check if from was specified, else use default
			if account == "" {
				account = accountList.getDefaultAccount()
			}

			// Resolving friendly names
			fromAddressResolved = accountList.getAddressByName(account)
		}
		toAddressResolved := accountList.getAddressByName(toAddress)

		// Parse lease field
		var leaseBytes [32]byte
		if cmd.Flags().Changed("lease") {
			leaseBytesRaw, err := base64.StdEncoding.DecodeString(lease)
			if err != nil {
				reportErrorf(malformedLease, lease, err)
			}
			if len(leaseBytesRaw) != 32 {
				reportErrorf(malformedLease, lease, fmt.Errorf("lease length %d != 32", len(leaseBytesRaw)))
			}
			copy(leaseBytes[:], leaseBytesRaw)
		}

		// Parse notes field
		noteBytes := parseNoteField(cmd)

		// If closing an account, resolve that address as well
		var closeToAddressResolved string
		if closeToAddress != "" {
			closeToAddressResolved = accountList.getAddressByName(closeToAddress)
		}

		client := ensureFullClient(dataDir)
		firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorf(err.Error())
		}
		payment, err := client.ConstructPayment(
			fromAddressResolved, toAddressResolved, fee, amount, noteBytes, closeToAddressResolved,
			leaseBytes, basics.Round(firstValid), basics.Round(lastValid),
		)
		if err != nil {
			reportErrorf(errorConstructingTX, err)
		}
		var stx transactions.SignedTxn
		if lsig.Logic != nil {
			params, err := client.SuggestedParams()
			if err != nil {
				reportErrorf(errorNodeStatus, err)
			}

			proto := protocol.ConsensusVersion(params.ConsensusVersion)
			uncheckedTxn := transactions.SignedTxn{
				Txn:  payment,
				Lsig: lsig,
			}
			err = verify.LogicSigSanityCheck(&uncheckedTxn, &verify.Context{Params: verify.Params{CurrProto: proto}})
			if err != nil {
				reportErrorf("%s: txn[0] error %s", txFilename, err)
			}
			stx = uncheckedTxn
		} else if program != nil {
			stx = transactions.SignedTxn{
				Txn: payment,
				Lsig: transactions.LogicSig{
					Logic: program,
					Args:  programArgs,
				},
			}
		} else {
			signTx := sign || (txFilename == "")
			stx, err = createSignedTransaction(client, signTx, dataDir, walletName, payment)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}
		}

		if txFilename == "" {
			// Broadcast the tx
			txid, err := client.BroadcastTransaction(stx)

			if err != nil {
				reportErrorf(errorBroadcastingTX, err)
			}

			// update information from Transaction
			fee = stx.Txn.Fee.Raw

			// Report tx details to user
			reportInfof(infoTxIssued, amount, fromAddressResolved, toAddressResolved, txid, fee)

			if !noWaitAfterSend {
				err = waitForCommit(client, txid)
				if err != nil {
					reportErrorf(err.Error())
				}
			}
		} else {
			err = writeFile(txFilename, protocol.Encode(stx), 0600)
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

		txnIDs := make(map[transactions.Txid]transactions.SignedTxn)
		var txns []transactions.SignedTxn
		for {
			var txn transactions.SignedTxn
			err = dec.Decode(&txn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}

			_, present := txnIDs[txn.ID()]
			if present {
				reportErrorf(txDupError, txn.ID().String(), txFilename)
			}

			txnIDs[txn.ID()] = txn
			txns = append(txns, txn)
		}

		txgroups := bookkeeping.SignedTxnsToGroups(txns)

		txnErrors := make(map[transactions.Txid]string)
		pendingTxns := make(map[transactions.Txid]string)
		for _, txgroup := range txgroups {
			// Broadcast the transaction
			err := client.BroadcastTransactionGroup(txgroup)
			if err != nil {
				for _, txn := range txgroup {
					txnErrors[txn.ID()] = err.Error()
				}
				reportWarnf(errorBroadcastingTX, err)
				continue
			}

			for _, txn := range txgroup {
				txidStr := txn.ID().String()
				reportInfof(infoRawTxIssued, txidStr)
				pendingTxns[txn.ID()] = txidStr
			}
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
			// Loop over transactions in the same order as the original file,
			// to preserve transaction groups.
			for _, txn := range txns {
				txid := txn.ID()
				errmsg, ok := txnErrors[txid]
				if !ok {
					continue
				}

				fmt.Printf("  %s: %s\n", txid, errmsg)
				rejectsData = append(rejectsData, protocol.Encode(txn)...)
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

func lsigFromArgs(lsig *transactions.LogicSig) {
	lsigBytes, err := readFile(logicSigFile)
	if err != nil {
		reportErrorf("%s: read failed, %s", logicSigFile, err)
	}
	err = protocol.Decode(lsigBytes, lsig)
	if err != nil {
		reportErrorf("%s: decode failed, %s", logicSigFile, err)
	}
	lsig.Args = getProgramArgs()
}

func getProto(versArg string) (protocol.ConsensusVersion, config.ConsensusParams) {
	cvers := protocol.ConsensusCurrentVersion
	if versArg != "" {
		cvers = protocol.ConsensusVersion(versArg)
	} else {
		dataDir := maybeSingleDataDir()
		if dataDir != "" {
			client := ensureAlgodClient(dataDir)
			params, err := client.SuggestedParams()
			if err == nil {
				cvers = protocol.ConsensusVersion(params.ConsensusVersion)
			}
			// else warning message?
		}
		// else warning message?
	}
	proto, ok := config.Consensus[cvers]
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid consensus version. Possible versions:\n")
		for xvers := range config.Consensus {
			fmt.Fprintf(os.Stderr, "\t%s\n", xvers)
		}
		os.Exit(1)
	}
	return cvers, proto
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

		var lsig transactions.LogicSig

		var client libgoal.Client
		var wh []byte
		var pw []byte

		if programSource != "" {
			if logicSigFile != "" {
				reportErrorln("goal clerk sign should have at most one of --program/-p or --logic-sig/-L")
			}
			lsig.Logic = assembleFile(programSource)
			lsig.Args = getProgramArgs()
		} else if logicSigFile != "" {
			lsigFromArgs(&lsig)
		}
		if lsig.Logic == nil {
			// sign the usual way
			dataDir := ensureSingleDataDir()
			client = ensureKmdClient(dataDir)
			wh, pw = ensureWalletHandleMaybePassword(dataDir, walletName, true)
		}

		var outData []byte
		dec := protocol.NewDecoderBytes(data)
		count := 0
		for {
			// transaction file comes in as a SignedTxn with no signature
			var uncheckedTxn transactions.SignedTxn
			err = dec.Decode(&uncheckedTxn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}

			var signedTxn transactions.SignedTxn
			if lsig.Logic != nil {
				proto, _ := getProto(protoVersion)
				uncheckedTxn.Lsig = lsig
				err = verify.LogicSigSanityCheck(&uncheckedTxn, &verify.Context{Params: verify.Params{CurrProto: proto}})
				if err != nil {
					reportErrorf("%s: txn[%d] error %s", txFilename, count, err)
				}
				signedTxn = uncheckedTxn
			} else {
				// sign the usual way
				signedTxn, err = client.SignTransactionWithWallet(wh, pw, uncheckedTxn.Txn)
				if err != nil {
					reportErrorf(errorSigningTX, err)
				}
			}

			outData = append(outData, protocol.Encode(signedTxn)...)
			count++
		}
		err = writeFile(outFilename, outData, 0600)
		if err != nil {
			reportErrorf(fileWriteError, outFilename, err)
		}
	},
}

var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "Group transactions together",
	Long:  `Form a transaction group.  The input file must contain one or more transactions that will form a group.  The output file will contain the same transactions, in order, with a group flag added to each transaction, which requires that the transactions must be committed together.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
		}

		dec := protocol.NewDecoderBytes(data)

		var txns []transactions.SignedTxn
		var group transactions.TxGroup
		for {
			var txn transactions.SignedTxn
			err = dec.Decode(&txn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}

			if !txn.Txn.Group.IsZero() {
				reportErrorf("Transaction %s is already part of a group.", txn.ID().String())
			}

			txns = append(txns, txn)
			group.TxGroupHashes = append(group.TxGroupHashes, crypto.HashObj(txn.Txn))
		}

		var outData []byte
		for _, txn := range txns {
			txn.Txn.Group = crypto.HashObj(group)
			outData = append(outData, protocol.Encode(txn)...)
		}

		err = writeFile(outFilename, outData, 0600)
		if err != nil {
			reportErrorf(fileWriteError, outFilename, err)
		}
	},
}

var splitCmd = &cobra.Command{
	Use:   "split",
	Short: "Split a file containing many transactions into one transaction per file",
	Long:  `Split a file containing many transactions.  The input file must contain one or more transactions.  These transactions will be written to individual files.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
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
				reportErrorf(txDecodeError, txFilename, err)
			}

			txns = append(txns, txn)
		}

		outExt := filepath.Ext(outFilename)
		outBase := outFilename[:len(outFilename)-len(outExt)]
		for idx, txn := range txns {
			fn := fmt.Sprintf("%s-%d%s", outBase, idx, outExt)
			err = writeFile(fn, protocol.Encode(txn), 0600)
			if err != nil {
				reportErrorf(fileWriteError, outFilename, err)
			}
			fmt.Printf("Wrote transaction %d to %s\n", idx, fn)
		}
	},
}

func assembleFile(fname string) (program []byte) {
	text, err := readFile(fname)
	if err != nil {
		reportErrorf("%s: %s\n", fname, err)
	}
	program, err = logic.AssembleString(string(text))
	if err != nil {
		reportErrorf("%s: %s\n", fname, err)
	}
	return program
}

func disassembleFile(fname, outname string) {
	program, err := readFile(fname)
	if err != nil {
		reportErrorf("%s: %s\n", fname, err)
	}
	// try parsing it as a msgpack LogicSig
	var lsig transactions.LogicSig
	err = protocol.Decode(program, &lsig)
	extra := ""
	if err == nil {
		// success, extract program to disassemble
		program = lsig.Logic
		if lsig.Sig != (crypto.Signature{}) || (!lsig.Msig.Blank()) || len(lsig.Args) > 0 {
			nologic := lsig
			nologic.Logic = nil
			ilsig := lsigToInspect(nologic)
			extra = "LogicSig: " + string(protocol.EncodeJSON(ilsig))
		}
	}
	text, err := logic.Disassemble(program)
	if err != nil {
		reportErrorf("%s: %s\n", fname, err)
	}
	if extra != "" {
		text = text + extra + "\n"
	}
	if outname == "" {
		os.Stdout.Write([]byte(text))
	} else {
		err = ioutil.WriteFile(outname, []byte(text), 0666)
		if err != nil {
			reportErrorf("%s: %s\n", outname, err)
		}
	}
}

var compileCmd = &cobra.Command{
	Use:   "compile",
	Short: "compile a contract program",
	Long:  "compile a contract program, report its address",
	Run: func(cmd *cobra.Command, args []string) {
		for _, fname := range args {
			if disassesmble {
				disassembleFile(fname, outFilename)
				continue
			}
			program := assembleFile(fname)
			outblob := program
			outname := outFilename
			if outname == "" {
				outname = fmt.Sprintf("%s.tok", fname)
			}
			if signProgram {
				dataDir := ensureSingleDataDir()
				accountList := makeAccountsList(dataDir)
				client := ensureKmdClient(dataDir)
				wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)

				// Check if from was specified, else use default
				if account == "" {
					account = accountList.getDefaultAccount()
					if account == "" {
						reportErrorln("no default account set. set one with 'goal account -f' or specify an account with '-a'.")
					}
					fmt.Printf("will use default account: %v\n", account)
				}
				signingAddressResolved := accountList.getAddressByName(account)

				signature, err := client.SignProgramWithWallet(wh, pw, signingAddressResolved, program)
				if err != nil {
					reportErrorf(errorSigningTX, err)
				}
				ls := transactions.LogicSig{Logic: program, Sig: signature}
				outblob = protocol.Encode(ls)
			}
			if !noProgramOutput {
				fout, err := os.Create(outname)
				if err != nil {
					reportErrorf("%s: %s\n", outname, err)
				}
				_, err = fout.Write(outblob)
				if err != nil {
					reportErrorf("%s: %s\n", outname, err)
				}
				err = fout.Close()
				if err != nil {
					reportErrorf("%s: %s\n", outname, err)
				}
			}
			if !signProgram {
				pd := logic.HashProgram(program)
				addr := basics.Address(pd)
				fmt.Printf("%s: %s\n", fname, addr.String())
			}
		}
	},
}

var dryrunCmd = &cobra.Command{
	Use:   "dryrun",
	Short: "test a program offline",
	Long:  "test a program offline under various conditions and verbosity",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
		}
		dec := protocol.NewDecoderBytes(data)
		stxns := make([]transactions.SignedTxn, 0, 10)
		for {
			var txn transactions.SignedTxn
			err = dec.Decode(&txn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}
			stxns = append(stxns, txn)
		}
		txgroup := make([]transactions.SignedTxn, len(stxns))
		for i, st := range stxns {
			txgroup[i] = st
		}
		if timeStamp <= 0 {
			timeStamp = time.Now().Unix()
		}
		_, params := getProto(protoVersion)
		for i, txn := range txgroup {
			if txn.Lsig.Blank() {
				continue
			}
			ep := logic.EvalParams{Txn: &txn, Proto: &params}
			cost, err := logic.Check(txn.Lsig.Logic, ep)
			if err != nil {
				reportErrorf("program failed Check: %s", err)
			}
			sb := strings.Builder{}
			ep = logic.EvalParams{
				Txn:        &txn,
				Proto:      &params,
				Trace:      &sb,
				TxnGroup:   txgroup,
				GroupIndex: i,
			}
			pass, err := logic.Eval(txn.Lsig.Logic, ep)
			// TODO: optionally include `inspect` output here?
			fmt.Fprintf(os.Stdout, "tx[%d] cost=%d trace:\n%s\n", i, cost, sb.String())
			if pass {
				fmt.Fprintf(os.Stdout, " - pass -\n")
			} else {
				fmt.Fprintf(os.Stdout, "REJECT\n")
			}
			if err != nil {
				fmt.Fprintf(os.Stdout, "ERROR: %s\n", err.Error())
			}
		}

	},
}
