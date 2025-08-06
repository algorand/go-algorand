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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"

	"github.com/spf13/cobra"
)

var (
	toAddress          string
	account            string
	amount             uint64
	txFilename         string
	rejectsFilename    string
	closeToAddress     string
	noProgramOutput    bool
	writeSourceMap     bool
	signProgram        bool
	programSource      string
	argB64Strings      []string
	disassemble        bool
	verbose            bool
	progByteFile       string
	msigParams         string
	logicSigFile       string
	timeStamp          int64
	protoVersion       string
	rekeyToAddress     string
	signerAddress      string
	rawOutput          bool
	requestFilename    string
	requestOutFilename string
	inspectTxid        bool

	simulateStartRound            basics.Round
	simulateAllowEmptySignatures  bool
	simulateAllowMoreLogging      bool
	simulateAllowMoreOpcodeBudget bool
	simulateExtraOpcodeBudget     int

	simulateFullTrace             bool
	simulateEnableRequestTrace    bool
	simulateStackChange           bool
	simulateScratchChange         bool
	simulateAppStateChange        bool
	simulateAllowUnnamedResources bool
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
	clerkCmd.AddCommand(dryrunRemoteCmd)
	clerkCmd.AddCommand(simulateCmd)

	// Wallet to be used for the clerk operation
	clerkCmd.PersistentFlags().StringVarP(&walletName, "wallet", "w", "", "Set the wallet to be used for the selected operation")

	// inspect flags
	inspectCmd.Flags().BoolVarP(&inspectTxid, "txid", "t", false, "Display the TxID for each transaction")

	// send flags
	sendCmd.Flags().StringVarP(&account, "from", "f", "", "Account address to send the money from (If not specified, uses default account)")
	sendCmd.Flags().StringVarP(&toAddress, "to", "t", "", "Address to send to money to (required)")
	sendCmd.Flags().Uint64VarP(&amount, "amount", "a", 0, "The amount to be transferred (required), in microAlgos")
	sendCmd.Flags().StringVarP(&closeToAddress, "close-to", "c", "", "Close account and send remainder to this address")
	sendCmd.Flags().StringVar(&rekeyToAddress, "rekey-to", "", "Rekey account to the given spending key/address. (Future transactions from this account will need to be signed with the new key.)")
	sendCmd.Flags().StringVarP(&programSource, "from-program", "F", "", "Program source file to use as account logic")
	sendCmd.Flags().StringVarP(&progByteFile, "from-program-bytes", "P", "", "Program binary to use as account logic")
	sendCmd.Flags().StringSliceVar(&argB64Strings, "argb64", nil, "Base64 encoded args to pass to transaction logic")
	sendCmd.Flags().StringVarP(&logicSigFile, "logic-sig", "L", "", "LogicSig to apply to transaction")
	sendCmd.Flags().StringVar(&msigParams, "msig-params", "", "Multisig preimage parameters - [threshold] [Address 1] [Address 2] ...\nUsed to add the necessary fields in case the account was rekeyed to a multisig account")
	sendCmd.MarkFlagRequired("to")
	sendCmd.MarkFlagRequired("amount")

	// Add common transaction flags
	addTxnFlags(sendCmd)

	// rawsend flags
	rawsendCmd.Flags().StringVarP(&txFilename, "filename", "f", "", "Filename of file containing raw transactions")
	rawsendCmd.Flags().StringVarP(&rejectsFilename, "rejects", "r", "", "Filename for writing rejects to (default is txFilename.rej)")
	rawsendCmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transactions to commit")
	rawsendCmd.MarkFlagRequired("filename")

	signCmd.Flags().StringVarP(&txFilename, "infile", "i", "", "Partially-signed transaction file to add signature to")
	signCmd.Flags().StringVarP(&outFilename, "outfile", "o", "", "Filename for writing the signed transaction")
	signCmd.Flags().StringVarP(&signerAddress, "signer", "S", "", "Address of key to sign with, if different from transaction \"from\" address due to rekeying")
	signCmd.Flags().StringVarP(&programSource, "program", "p", "", "Program source file to use as account logic")
	signCmd.Flags().StringVarP(&logicSigFile, "logic-sig", "L", "", "LogicSig to apply to transaction")
	signCmd.Flags().StringSliceVar(&argB64Strings, "argb64", nil, "Base64 encoded args to pass to transaction logic")
	signCmd.Flags().StringVarP(&protoVersion, "proto", "P", "", "Consensus protocol version id string")
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

	compileCmd.Flags().BoolVarP(&disassemble, "disassemble", "D", false, "Disassemble a compiled program")
	compileCmd.Flags().BoolVarP(&noProgramOutput, "no-out", "n", false, "Don't write contract program binary")
	compileCmd.Flags().BoolVarP(&writeSourceMap, "map", "m", false, "Write out source map")
	compileCmd.Flags().BoolVarP(&signProgram, "sign", "s", false, "Sign program, output is a binary signed LogicSig record")
	compileCmd.Flags().StringVarP(&outFilename, "outfile", "o", "", "Filename to write program bytes or signed LogicSig to")
	compileCmd.Flags().StringVarP(&account, "account", "a", "", "Account address to sign the program (If not specified, uses default account)")

	dryrunCmd.Flags().StringVarP(&txFilename, "txfile", "t", "", "Transaction or transaction-group to test")
	dryrunCmd.Flags().StringVarP(&protoVersion, "proto", "P", "", "Consensus protocol version id string")
	dryrunCmd.Flags().BoolVar(&dumpForDryrun, "dryrun-dump", false, "Dump in dryrun format acceptable by dryrun REST api instead of running")
	dryrunCmd.Flags().Var(&dumpForDryrunFormat, "dryrun-dump-format", "Dryrun dump format: "+dumpForDryrunFormat.AllowedString())
	dryrunCmd.Flags().StringSliceVar(&dumpForDryrunAccts, "dryrun-accounts", nil, "Additional accounts to include into dryrun request obj")
	dryrunCmd.Flags().StringVarP(&outFilename, "outfile", "o", "", "Filename for writing dryrun state object")
	dryrunCmd.MarkFlagRequired("txfile")

	dryrunRemoteCmd.Flags().StringVarP(&txFilename, "dryrun-state", "D", "", "Dryrun request object to run")
	dryrunRemoteCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print more info")
	dryrunRemoteCmd.Flags().BoolVarP(&rawOutput, "raw", "r", false, "Output raw response from algod")
	dryrunRemoteCmd.MarkFlagRequired("dryrun-state")

	simulateCmd.Flags().StringVarP(&txFilename, "txfile", "t", "", "Transaction or transaction-group to test. Mutually exclusive with --request")
	simulateCmd.Flags().StringVar(&requestFilename, "request", "", "Simulate request object to run. Mutually exclusive with --txfile")
	simulateCmd.Flags().StringVar(&requestOutFilename, "request-only-out", "", "Filename for writing simulate request object. If provided, the command will only write the request object and exit. No simulation will happen")
	simulateCmd.Flags().StringVarP(&outFilename, "result-out", "o", "", "Filename for writing simulation result")
	simulateCmd.Flags().Uint64Var((*uint64)(&simulateStartRound), "round", 0, "Specify the round after which the simulation will take place. If not specified, the simulation will take place after the latest round.")
	simulateCmd.Flags().BoolVar(&simulateAllowEmptySignatures, "allow-empty-signatures", false, "Allow transactions without signatures to be simulated as if they had correct signatures")
	simulateCmd.Flags().BoolVar(&simulateAllowMoreLogging, "allow-more-logging", false, "Lift the limits on log opcode during simulation")
	simulateCmd.Flags().BoolVar(&simulateAllowMoreOpcodeBudget, "allow-more-opcode-budget", false, "Apply max extra opcode budget for apps per transaction group (default 320000) during simulation")
	simulateCmd.Flags().IntVar(&simulateExtraOpcodeBudget, "extra-opcode-budget", 0, "Apply extra opcode budget for apps per transaction group during simulation")

	simulateCmd.Flags().BoolVar(&simulateFullTrace, "full-trace", false, "Enable all options for simulation execution trace")
	simulateCmd.Flags().BoolVar(&simulateEnableRequestTrace, "trace", false, "Enable simulation time execution trace of app calls")
	simulateCmd.Flags().BoolVar(&simulateStackChange, "stack", false, "Report stack change during simulation time")
	simulateCmd.Flags().BoolVar(&simulateScratchChange, "scratch", false, "Report scratch change during simulation time")
	simulateCmd.Flags().BoolVar(&simulateAppStateChange, "state", false, "Report application state changes during simulation time")
	simulateCmd.Flags().BoolVar(&simulateAllowUnnamedResources, "allow-unnamed-resources", false, "Allow access to unnamed resources during simulation")
}

var clerkCmd = &cobra.Command{
	Use:   "clerk",
	Short: "Provides the tools to control transactions ",
	Long:  `Collection of commands to support the management of transaction information.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

func waitForCommit(client libgoal.Client, txid string, transactionLastValidRound basics.Round) (txn model.PendingTransactionResponse, err error) {
	// Get current round information
	stat, err := client.Status()
	if err != nil {
		return model.PendingTransactionResponse{}, fmt.Errorf(errorRequestFail, err)
	}

	for {
		// Check if we know about the transaction yet
		txn, err = client.PendingTransactionInformation(txid)
		if err != nil {
			return model.PendingTransactionResponse{}, fmt.Errorf(errorRequestFail, err)
		}

		if txn.ConfirmedRound != nil && *txn.ConfirmedRound > 0 {
			reportInfof(infoTxCommitted, txid, *txn.ConfirmedRound)
			break
		}

		if txn.PoolError != "" {
			return model.PendingTransactionResponse{}, fmt.Errorf(txPoolError, txid, txn.PoolError)
		}

		// check if we've already committed to the block number equals to the transaction's last valid round.
		// if this is the case, the transaction would not be included in the blockchain, and we can exit right
		// here.
		if transactionLastValidRound > 0 && stat.LastRound >= transactionLastValidRound {
			return model.PendingTransactionResponse{}, fmt.Errorf(errorTransactionExpired, txid)
		}

		reportInfof(infoTxPending, txid, stat.LastRound)
		stat, err = client.WaitForRound(stat.LastRound + 1)
		if err != nil {
			return model.PendingTransactionResponse{}, fmt.Errorf(errorRequestFail, err)
		}
	}
	return
}

func createSignedTransaction(client libgoal.Client, signTx bool, dataDir string, walletName string, tx transactions.Transaction, signer basics.Address) (stxn transactions.SignedTxn, err error) {
	if signTx {
		// Sign the transaction
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
		if signer.IsZero() {
			stxn, err = client.SignTransactionWithWallet(wh, pw, tx)
		} else {
			stxn, err = client.SignTransactionWithWalletAndSigner(wh, pw, signer.String(), tx)
		}
		return
	}

	// Wrap in a transactions.SignedTxn with an empty sig.
	// This way protocol.Encode will encode the transaction type
	stxn, err = transactions.AssembleSignedTxn(tx, crypto.Signature{}, crypto.MultisigSig{})
	if err != nil {
		return
	}

	stxn = populateBlankMultisig(client, dataDir, walletName, stxn)
	return
}

func writeSignedTxnsToFile(stxns []transactions.SignedTxn, filename string) error {
	var outData []byte
	for i := range stxns {
		outData = append(outData, protocol.Encode(&stxns[i])...)
	}

	return writeFile(filename, outData, 0600)
}

func writeTxnToFile(client libgoal.Client, signTx bool, dataDir string, walletName string, tx transactions.Transaction, filename string) error {
	var authAddr basics.Address
	var err error
	if signerAddress != "" {
		authAddr, err = basics.UnmarshalChecksumAddress(signerAddress)
		if err != nil {
			reportErrorf("Signer invalid (%s): %v", signerAddress, err)
		}
	}

	stxn, err := createSignedTransaction(client, signTx, dataDir, walletName, tx, authAddr)
	if err != nil {
		return err
	}
	// Write the SignedTxn to the output file
	return writeSignedTxnsToFile([]transactions.SignedTxn{stxn}, filename)
}

func getB64Args(args []string) [][]byte {
	if len(args) == 0 {
		return nil
	}
	programArgs := make([][]byte, len(args))
	for i, argstr := range args {
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

func getProgramArgs() [][]byte {
	return getB64Args(argB64Strings)
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

func parseLease(cmd *cobra.Command) (leaseBytes [32]byte) {
	// Parse lease field
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
	return
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send money to an address",
	Long:  `Send money from one account to another. Note: by default, the money will be withdrawn from the default account. Creates a transaction sending amount tokens from fromAddr to toAddr. If the optional --fee is not provided, the transaction will use the recommended amount. If the optional --firstvalid and --lastvalid are provided, the transaction will only be valid from round firstValid to round lastValid. If broadcast of the transaction is successful, the transaction ID will be returned.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// -s is invalid without -o
		if outFilename == "" && sign {
			reportErrorln(soFlagError)
		}

		// --msig-params is invalid without -o
		if outFilename == "" && msigParams != "" {
			reportErrorln(noOutputFileError)
		}

		checkTxValidityPeriodCmdFlags(cmd)

		dataDir := datadir.EnsureSingleDataDir()
		accountList := makeAccountsList(dataDir)

		var program []byte = nil
		var programArgs [][]byte = nil
		var lsig transactions.LogicSig
		var err error
		if progByteFile != "" {
			if programSource != "" || logicSigFile != "" {
				reportErrorln("should use at most one of --from-program/-F or --from-program-bytes/-P --logic-sig/-L")
			}
			program, err = readFile(progByteFile)
			if err != nil {
				reportErrorf("%s: %s", progByteFile, err)
			}
		} else if programSource != "" {
			if logicSigFile != "" {
				reportErrorln("should use at most one of --from-program/-F or --from-program-bytes/-P --logic-sig/-L")
			}
			program = assembleFile(programSource, false)
		} else if logicSigFile != "" {
			lsigFromArgs(&lsig)
		}
		if program != nil {
			if account == "" {
				ph := logic.HashProgram(program)
				pha := basics.Address(ph)
				account = pha.String()
			}
			programArgs = getProgramArgs()
		} else {
			// Check if from was specified, else use default
			if account == "" {
				account = accountList.getDefaultAccount()
			}
		}
		fromAddressResolved := accountList.getAddressByName(account)
		toAddressResolved := accountList.getAddressByName(toAddress)

		// Parse notes and lease fields
		noteBytes := parseNoteField(cmd)
		leaseBytes := parseLease(cmd)

		// If closing an account, resolve that address as well
		var closeToAddressResolved string
		if closeToAddress != "" {
			closeToAddressResolved = accountList.getAddressByName(closeToAddress)
		}

		// If rekeying, parse that address
		// (we don't use accountList.getAddressByName because this address likely doesn't correspond to an account)
		var rekeyTo basics.Address
		if rekeyToAddress != "" {
			var err1 error
			rekeyTo, err1 = basics.UnmarshalChecksumAddress(rekeyToAddress)
			if err1 != nil {
				reportErrorln(err1)
			}
		}
		client := ensureFullClient(dataDir)
		firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, numValidRounds)
		if err != nil {
			reportErrorln(err)
		}
		payment, err := client.ConstructPayment(
			fromAddressResolved, toAddressResolved, fee, amount, noteBytes, closeToAddressResolved,
			leaseBytes, firstValid, lastValid,
		)
		if err != nil {
			reportErrorf(errorConstructingTX, err)
		}
		if !rekeyTo.IsZero() {
			payment.RekeyTo = rekeyTo
		}

		// ConstructPayment fills in the suggested fee when fee=0. But if the user actually used --fee=0 on the
		// commandline, we ought to do what they asked (especially now that zero or low fees make sense in
		// combination with other txns that cover the groups's fee.
		explicitFee := cmd.Flags().Changed("fee")
		if explicitFee {
			payment.Fee = basics.MicroAlgos{Raw: fee}
		}

		var authAddr basics.Address
		if signerAddress != "" {
			authAddr, err = basics.UnmarshalChecksumAddress(signerAddress)
			if err != nil {
				reportErrorf("Signer invalid (%s): %v", signerAddress, err)
			}
		}

		var stx transactions.SignedTxn
		if lsig.Logic != nil {

			params, err1 := client.SuggestedParams()
			if err1 != nil {
				reportErrorf(errorNodeStatus, err1)
			}
			proto := protocol.ConsensusVersion(params.ConsensusVersion)
			uncheckedTxn := transactions.SignedTxn{
				Txn:  payment,
				Lsig: lsig,
			}
			blockHeader := bookkeeping.BlockHeader{
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: proto,
				},
			}
			groupCtx, err1 := verify.PrepareGroupContext([]transactions.SignedTxn{uncheckedTxn}, &blockHeader, nil, nil)
			if err1 == nil {
				err1 = verify.LogicSigSanityCheck(0, groupCtx)
			}
			if err1 != nil {
				reportErrorf("%s: txn error %s", outFilename, err1)
			}
			stx = uncheckedTxn
		} else if program != nil {
			stx = transactions.SignedTxn{
				Txn: payment,
				Lsig: transactions.LogicSig{
					Logic: program,
					Args:  programArgs,
				},
				AuthAddr: authAddr,
			}
		} else {
			signTx := sign || (outFilename == "")
			if signerAddress != "" {
				if !signTx {
					reportErrorf("Signer specified when txn won't be signed")
				}
			}
			stx, err = createSignedTransaction(client, signTx, dataDir, walletName, payment, authAddr)
			if err != nil {
				reportErrorf(errorSigningTX, err)
			}
		}

		// Handle the case where the user wants to send to an account that was rekeyed to a multisig account
		if msigParams != "" {
			// Decode params
			params := strings.Split(msigParams, " ")
			if len(params) < 3 {
				reportErrorf(msigParseError, "Not enough arguments to create the multisig address.\nPlease make sure to specify the threshold and at least 2 addresses\n")
			}

			threshold, err1 := strconv.ParseUint(params[0], 10, 8)
			if err1 != nil || threshold < 1 || threshold > 255 {
				reportErrorf(msigParseError, "Failed to parse the threshold. Make sure it's a number between 1 and 255")
			}

			// Convert the addresses into public keys
			pks := make([]crypto.PublicKey, len(params[1:]))
			for i, addrStr := range params[1:] {
				addr, err2 := basics.UnmarshalChecksumAddress(addrStr)
				if err2 != nil {
					reportErrorf(failDecodeAddressError, err2)
				}
				pks[i] = crypto.PublicKey(addr)
			}

			addr, err1 := crypto.MultisigAddrGen(1, uint8(threshold), pks)
			if err1 != nil {
				reportErrorf(msigParseError, err1)
			}

			// Generate the multisig and assign to the txn
			stx.Msig = crypto.MultisigPreimageFromPKs(1, uint8(threshold), pks)

			// Append the signer since it's a rekey txn
			if basics.Address(addr) == stx.Txn.Sender {
				reportWarnln(rekeySenderTargetSameError)
			}
			stx.AuthAddr = basics.Address(addr)
		}

		if outFilename == "" {
			// Broadcast the tx
			txid, err1 := client.BroadcastTransaction(stx)

			if err1 != nil {
				reportErrorf(errorBroadcastingTX, err1)
			}

			// update information from Transaction
			fee = stx.Txn.Fee.Raw

			// Report tx details to user
			reportInfof(infoTxIssued, amount, fromAddressResolved, toAddressResolved, txid, fee)

			if !noWaitAfterSend {
				_, err1 = waitForCommit(client, txid, lastValid)
				if err1 != nil {
					reportErrorln(err1)
				}
			}
		} else {
			if dumpForDryrun {
				err = writeDryrunReqToFile(client, stx, outFilename)
			} else {
				err = writeFile(outFilename, protocol.Encode(&stx), 0600)
			}
			if err != nil {
				reportErrorln(err)
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

		dec := protocol.NewMsgpDecoderBytes(data)
		client := ensureAlgodClient(datadir.EnsureSingleDataDir())

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
			err1 := client.BroadcastTransactionGroup(txgroup)
			if err1 != nil {
				for _, txn := range txgroup {
					txnErrors[txn.ID()] = err1.Error()
				}
				reportWarnf(errorBroadcastingTX, err1)
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

				if txn.ConfirmedRound != nil && *txn.ConfirmedRound > 0 {
					reportInfof(infoTxCommitted, txidStr, *txn.ConfirmedRound)
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
				rejectsData = append(rejectsData, protocol.Encode(&txn)...)
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
	Use:   "inspect [input file 1] [input file 2]...",
	Short: "Print a transaction file",
	Long:  `Loads a transaction file, attempts to decode the transaction, and displays the decoded information.`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, txFilename := range args {
			data, err := readFile(txFilename)
			if err != nil {
				reportErrorf(fileReadError, txFilename, err)
			}

			dec := protocol.NewMsgpDecoderBytes(data)
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
				if inspectTxid {
					fmt.Printf("%s[%d] - %s\n%s\n\n", txFilename, count, sti.Txn.ID(), string(protocol.EncodeJSON(sti)))
				} else {
					fmt.Printf("%s[%d]\n%s\n\n", txFilename, count, string(protocol.EncodeJSON(sti)))
				}
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
		dataDir := datadir.MaybeSingleDataDir()
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
	Use:   "sign -i [input file] -o [output file]",
	Short: "Sign a transaction file",
	Long:  `Sign the passed transaction file, which may contain one or more transactions. If the infile and the outfile are the same, this overwrites the file with the new, signed data.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
		}

		var lsig transactions.LogicSig
		var authAddr basics.Address
		var client libgoal.Client
		var wh []byte
		var pw []byte

		if programSource != "" {
			if logicSigFile != "" {
				reportErrorln("goal clerk sign should have at most one of --program/-p or --logic-sig/-L")
			}
			lsig.Logic = assembleFile(programSource, false)
			lsig.Args = getProgramArgs()
		} else if logicSigFile != "" {
			lsigFromArgs(&lsig)
		}
		if lsig.Logic == nil {
			// sign the usual way
			dataDir := datadir.EnsureSingleDataDir()
			client = ensureKmdClient(dataDir)
			wh, pw = ensureWalletHandleMaybePassword(dataDir, walletName, true)
		} else if signerAddress != "" {
			authAddr, err = basics.UnmarshalChecksumAddress(signerAddress)
			if err != nil {
				reportErrorf("Signer invalid (%s): %v", signerAddress, err)
			}
		}

		var outData []byte
		dec := protocol.NewMsgpDecoderBytes(data)
		// read the entire file and prepare in-memory copy of each signed transaction, with grouping.
		txnGroups := make(map[crypto.Digest][]*transactions.SignedTxn)
		var groupsOrder []crypto.Digest
		txnIndex := make(map[*transactions.SignedTxn]int)
		count := 0
		for {
			uncheckedTxn := new(transactions.SignedTxn)
			err = dec.Decode(uncheckedTxn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}
			group := uncheckedTxn.Txn.Group
			if group.IsZero() {
				// create a dummy group.
				randGroupBytes := crypto.Digest{}
				crypto.RandBytes(randGroupBytes[:])
				group = randGroupBytes
			}
			if _, hasGroup := txnGroups[group]; !hasGroup {
				// add a new group as needed.
				groupsOrder = append(groupsOrder, group)

			}
			txnGroups[group] = append(txnGroups[group], uncheckedTxn)
			txnIndex[uncheckedTxn] = count
			count++
		}

		consensusVersion, _ := getProto(protoVersion)
		contextHdr := bookkeeping.BlockHeader{
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: consensusVersion,
			},
		}

		for _, group := range groupsOrder {
			txnGroup := []transactions.SignedTxn{}
			for _, txn := range txnGroups[group] {
				if lsig.Logic != nil {
					txn.Lsig = lsig
					if signerAddress != "" {
						txn.AuthAddr = authAddr
					}
				}
				txnGroup = append(txnGroup, *txn)
			}
			var groupCtx *verify.GroupContext
			if lsig.Logic != nil {
				groupCtx, err = verify.PrepareGroupContext(txnGroup, &contextHdr, nil, nil)
				if err != nil {
					// this error has to be unsupported protocol
					reportErrorf("%s: %v", txFilename, err)
				}
			}
			for i := range txnGroup {
				var signedTxn transactions.SignedTxn
				if lsig.Logic != nil {
					err = verify.LogicSigSanityCheck(i, groupCtx)
					if err != nil {
						reportErrorf("%s: txn[%d] error %s", txFilename, txnIndex[txnGroups[group][i]], err)
					}
					signedTxn = txnGroup[i]
				} else {
					// sign the usual way
					signedTxn, err = client.SignTransactionWithWalletAndSigner(wh, pw, signerAddress, txnGroup[i].Txn)
					if err != nil {
						reportErrorf(errorSigningTX, err)
					}
				}
				outData = append(outData, protocol.Encode(&signedTxn)...)
			}
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
	Long:  `Form a transaction group.  The input file must contain one or more unsigned transactions that will form a group.  The output file will contain the same transactions, in order, with a group flag added to each transaction, which requires that the transactions must be committed together. The group command would retain the logic signature, if present, as the TEAL program could verify the group using a logic signature argument.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
		}

		dec := protocol.NewMsgpDecoderBytes(data)

		var stxns []transactions.SignedTxn
		var group transactions.TxGroup
		transactionIdx := 0
		for {
			var stxn transactions.SignedTxn
			// we decode the file into a SignedTxn since we want to verify the absence of the signature as well as preserve the AuthAddr.
			err = dec.Decode(&stxn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}

			if !stxn.Txn.Group.IsZero() {
				reportErrorf("Transaction #%d with ID of %s is already part of a group.", transactionIdx, stxn.ID().String())
			}

			if (!stxn.Sig.Blank()) || (!stxn.Msig.Blank()) {
				reportErrorf("Transaction #%d with ID of %s is already signed", transactionIdx, stxn.ID().String())
			}

			stxns = append(stxns, stxn)
			group.TxGroupHashes = append(group.TxGroupHashes, crypto.Digest(stxn.ID()))
			transactionIdx++
		}

		groupHash := crypto.HashObj(group)
		for i := range stxns {
			stxns[i].Txn.Group = groupHash
		}

		err = writeSignedTxnsToFile(stxns, outFilename)
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
		txns := decodeTxnsFromFile(txFilename)
		outExt := filepath.Ext(outFilename)
		outBase := outFilename[:len(outFilename)-len(outExt)]
		for idx := range txns {
			fn := fmt.Sprintf("%s-%d%s", outBase, idx, outExt)
			err := writeFile(fn, protocol.Encode(&txns[idx]), 0600)
			if err != nil {
				reportErrorf(fileWriteError, outFilename, err)
			}
			fmt.Printf("Wrote transaction %d to %s\n", idx, fn)
		}
	},
}

func mustReadFile(fname string) []byte {
	contents, err := readFile(fname)
	if err != nil {
		reportErrorf("%s: %s", fname, err)
	}
	return contents
}

func assembleFileImpl(fname string, printWarnings bool) *logic.OpStream {
	text, err := readFile(fname)
	if err != nil {
		reportErrorf("%s: %s", fname, err)
	}
	ops, err := logic.AssembleString(string(text))
	if err != nil {
		ops.ReportMultipleErrors(fname, os.Stderr)
		reportErrorf("%s: %s", fname, err)
	}

	if printWarnings && len(ops.Warnings) != 0 {
		for _, warning := range ops.Warnings {
			reportWarnRawln(warning.Error())
		}
		plural := "s"
		if len(ops.Warnings) == 1 {
			plural = ""
		}
		reportWarnRawf("%d warning%s", len(ops.Warnings), plural)
	}

	return ops
}

func assembleFile(fname string, printWarnings bool) (program []byte) {
	ops := assembleFileImpl(fname, printWarnings)
	return ops.Program
}

func assembleFileWithMap(sourceFile string, outFile string, printWarnings bool) ([]byte, logic.SourceMap, error) {
	ops := assembleFileImpl(sourceFile, printWarnings)
	pathToSourceFromSourceMap, err := determinePathToSourceFromSourceMap(sourceFile, outFile)
	if err != nil {
		return nil, logic.SourceMap{}, err
	}
	return ops.Program, logic.GetSourceMap([]string{pathToSourceFromSourceMap}, ops.OffsetToSource), nil
}

func determinePathToSourceFromSourceMap(sourceFile string, outFile string) (string, error) {
	if sourceFile == stdinFileNameValue {
		return "<stdin>", nil
	}
	sourceFileAbsolute, err := filepath.Abs(sourceFile)
	if err != nil {
		return "", fmt.Errorf("could not determine absolute path to source file '%s': %w", sourceFile, err)
	}
	if outFile == stdoutFilenameValue {
		return sourceFileAbsolute, nil
	}
	outFileAbsolute, err := filepath.Abs(outFile)
	if err != nil {
		return "", fmt.Errorf("could not determine absolute path to output file '%s': %w", outFile, err)
	}
	pathToSourceFromSourceMap, err := filepath.Rel(filepath.Dir(outFileAbsolute), sourceFileAbsolute)
	if err != nil {
		return "", fmt.Errorf("could not determine path from source map to source: %w", err)
	}
	return pathToSourceFromSourceMap, nil
}

func disassembleFile(fname, outname string) {
	program, err := readFile(fname)
	if err != nil {
		reportErrorf("%s: %s", fname, err)
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
		reportErrorf("%s: %s", fname, err)
	}
	if extra != "" {
		text = text + extra + "\n"
	}
	if outname == "" {
		os.Stdout.Write([]byte(text))
	} else {
		err = writeFile(outname, []byte(text), 0666)
		if err != nil {
			reportErrorf("%s: %s", outname, err)
		}
	}
}

var compileCmd = &cobra.Command{
	Use:   "compile [input file 1] [input file 2]...",
	Short: "Compile a contract program",
	Long:  "Reads a TEAL contract program and compiles it to binary output and contract address.",
	Run: func(cmd *cobra.Command, args []string) {
		for _, fname := range args {
			if disassemble {
				disassembleFile(fname, outFilename)
				continue
			}
			outname := outFilename
			if outname == "" {
				if fname == stdinFileNameValue {
					outname = stdoutFilenameValue
				} else {
					outname = fmt.Sprintf("%s.tok", fname)
				}
			}
			shouldPrintAdditionalInfo := outname != stdoutFilenameValue
			program, sourceMap, err := assembleFileWithMap(fname, outname, true)
			if err != nil {
				reportErrorf("Could not assemble: %s", err)
			}
			outblob := program
			if signProgram {
				dataDir := datadir.EnsureSingleDataDir()
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
				outblob = protocol.Encode(&ls)
			}
			if !noProgramOutput {
				err := writeFile(outname, outblob, 0666)
				if err != nil {
					reportErrorf("%s: %s", outname, err)
				}
			}
			if writeSourceMap {
				if outname == stdoutFilenameValue {
					reportErrorf("%s: %s", outname, "cannot print map to stdout")
				}
				mapname := outname + ".map"
				pcblob, err := json.Marshal(sourceMap)
				if err != nil {
					reportErrorf("%s: %s", mapname, err)
				}
				err = writeFile(mapname, pcblob, 0666)
				if err != nil {
					reportErrorf("%s: %s", mapname, err)
				}
			}
			if !signProgram && shouldPrintAdditionalInfo {
				pd := logic.HashProgram(program)
				addr := basics.Address(pd)
				fmt.Printf("%s: %s\n", fname, addr.String())
			}
		}
	},
}

var dryrunCmd = &cobra.Command{
	Use:   "dryrun",
	Short: "Test a program offline",
	Long:  "Test a TEAL program offline under various conditions and verbosity.",
	Run: func(cmd *cobra.Command, args []string) {
		stxns := decodeTxnsFromFile(txFilename)
		proto, params := getProto(protoVersion)
		if dumpForDryrun {
			// Write dryrun data to file
			dataDir := datadir.EnsureSingleDataDir()
			client := ensureFullClient(dataDir)
			accts := util.Map(dumpForDryrunAccts, cliAddress)
			data, err := libgoal.MakeDryrunStateBytes(client, nil, stxns, accts, string(proto), dumpForDryrunFormat.String())
			if err != nil {
				reportErrorln(err)
			}
			writeFile(outFilename, data, 0600)
			return
		}

		if timeStamp <= 0 {
			timeStamp = time.Now().Unix()
		}

		lSigPooledSize := 0
		for i, txn := range stxns {
			if txn.Lsig.Blank() {
				continue
			}
			lsigLen := txn.Lsig.Len()
			lSigPooledSize += lsigLen
			if !params.EnableLogicSigSizePooling && uint64(lsigLen) > params.LogicSigMaxSize {
				reportErrorf("program size too large: %d > %d", len(txn.Lsig.Logic), params.LogicSigMaxSize)
			}
			ep := logic.NewSigEvalParams(stxns, &params, logic.NoHeaderLedger{})

			err := logic.CheckSignature(i, ep)
			if err != nil {
				reportErrorf("program failed Check: %s", err)
			}
			ep.Trace = &strings.Builder{}
			pass, err := logic.EvalSignature(i, ep)
			// TODO: optionally include `inspect` output here?
			fmt.Fprintf(os.Stdout, "tx[%d] trace:\n%s\n", i, ep.Trace.String())
			if pass {
				fmt.Fprintf(os.Stdout, " - pass -\n")
			} else {
				fmt.Fprintf(os.Stdout, "REJECT\n")
			}
			if err != nil {
				fmt.Fprintf(os.Stdout, "ERROR: %s\n", err.Error())
			}
		}
		lSigMaxPooledSize := len(stxns) * int(params.LogicSigMaxSize)
		if params.EnableLogicSigSizePooling && lSigPooledSize > lSigMaxPooledSize {
			reportErrorf("total lsigs size too large: %d > %d", lSigPooledSize, lSigMaxPooledSize)
		}

	},
}

var dryrunRemoteCmd = &cobra.Command{
	Use:   "dryrun-remote",
	Short: "Test a program with algod's dryrun REST endpoint",
	Long:  "Test a TEAL program with algod's dryrun REST endpoint under various conditions and verbosity.",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
		}

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		resp, err := client.Dryrun(data)
		if err != nil {
			reportErrorf("dryrun-remote: %s", err.Error())
		}
		if rawOutput {
			fmt.Fprint(os.Stdout, string(protocol.EncodeJSON(&resp)))
			return
		}

		stackToString := func(stack []model.TealValue) string {
			result := make([]string, len(stack))
			for i, sv := range stack {
				if sv.Type == uint64(basics.TealBytesType) {
					result[i] = heuristicFormatStr(sv.Bytes)
				} else {
					result[i] = fmt.Sprintf("%d", sv.Uint)
				}
			}
			return strings.Join(result, " ")
		}
		if len(resp.Txns) > 0 {
			for i, txnResult := range resp.Txns {
				var msgs []string
				var trace []model.DryrunState
				if txnResult.AppCallMessages != nil && len(*txnResult.AppCallMessages) > 0 {
					msgs = *txnResult.AppCallMessages
					if txnResult.AppCallTrace != nil {
						trace = *txnResult.AppCallTrace
					}
				} else if txnResult.LogicSigMessages != nil && len(*txnResult.LogicSigMessages) > 0 {
					msgs = *txnResult.LogicSigMessages
					if txnResult.LogicSigTrace != nil {
						trace = *txnResult.LogicSigTrace
					}
				}
				if txnResult.BudgetConsumed != nil {
					fmt.Fprintf(os.Stdout, "tx[%d] budget consumed: %d\n", i, *txnResult.BudgetConsumed)
				}
				if txnResult.BudgetAdded != nil {
					fmt.Fprintf(os.Stdout, "tx[%d] budget added: %d\n", i, *txnResult.BudgetAdded)
				}

				fmt.Fprintf(os.Stdout, "tx[%d] messages:\n", i)
				for _, msg := range msgs {
					fmt.Fprintf(os.Stdout, "%s\n", msg)
				}
				if verbose && len(trace) > 0 {
					fmt.Fprintf(os.Stdout, "tx[%d] trace:\n", i)
					for _, item := range trace {
						fmt.Fprintf(os.Stdout, "%4d (%04x): %s [%s]\n",
							item.Line, item.Pc, txnResult.Disassembly[item.Line-1], stackToString(item.Stack))
					}
				}
			}
		}
	},
}

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Simulate a transaction or transaction group with algod's simulate REST endpoint",
	Long:  `Simulate a transaction or transaction group with algod's simulate REST endpoint under various configurations.`,
	Run: func(cmd *cobra.Command, args []string) {
		txProvided := cmd.Flags().Changed("txfile")
		requestProvided := cmd.Flags().Changed("request")
		if txProvided == requestProvided {
			reportErrorf("exactly one of --txfile or --request must be provided")
		}

		extraBudgetProvided := cmd.Flags().Changed("extra-opcode-budget")
		if simulateAllowMoreOpcodeBudget && extraBudgetProvided {
			reportErrorf("--allow-extra-opcode-budget and --extra-opcode-budget are mutually exclusive")
		}
		if simulateAllowMoreOpcodeBudget {
			simulateExtraOpcodeBudget = simulation.MaxExtraOpcodeBudget
		}

		requestOutProvided := cmd.Flags().Changed("request-only-out")
		resultOutProvided := cmd.Flags().Changed("result-out")
		if requestOutProvided && resultOutProvided {
			reportErrorf("--request-only-out and --result-out are mutually exclusive")
		}

		if requestOutProvided {
			// If request-only-out is provided, only create a request and write it. Do not actually
			// simulate.
			if requestProvided {
				reportErrorf("--request-only-out and --request are mutually exclusive")
			}
			txgroup := decodeTxnsFromFile(txFilename)
			simulateRequest := v2.PreEncodedSimulateRequest{
				TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
					{
						Txns: txgroup,
					},
				},
				Round:                 simulateStartRound,
				AllowEmptySignatures:  simulateAllowEmptySignatures,
				AllowMoreLogging:      simulateAllowMoreLogging,
				AllowUnnamedResources: simulateAllowUnnamedResources,
				ExtraOpcodeBudget:     simulateExtraOpcodeBudget,
				ExecTraceConfig:       traceCmdOptionToSimulateTraceConfigModel(),
			}
			err := writeFile(requestOutFilename, protocol.EncodeJSON(simulateRequest), 0600)
			if err != nil {
				reportErrorf("write file error: %s", err.Error())
			}
			return
		}

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureFullClient(dataDir)
		var simulateResponse v2.PreEncodedSimulateResponse
		var responseErr error
		if txProvided {
			txgroup := decodeTxnsFromFile(txFilename)
			simulateRequest := v2.PreEncodedSimulateRequest{
				TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
					{
						Txns: txgroup,
					},
				},
				Round:                 simulateStartRound,
				AllowEmptySignatures:  simulateAllowEmptySignatures,
				AllowMoreLogging:      simulateAllowMoreLogging,
				AllowUnnamedResources: simulateAllowUnnamedResources,
				ExtraOpcodeBudget:     simulateExtraOpcodeBudget,
				ExecTraceConfig:       traceCmdOptionToSimulateTraceConfigModel(),
			}
			simulateResponse, responseErr = client.SimulateTransactions(simulateRequest)
		} else {
			data, err := readFile(requestFilename)
			if err != nil {
				reportErrorf(fileReadError, requestFilename, err)
			}
			simulateResponse, responseErr = client.SimulateTransactionsRaw(data)
		}

		if responseErr != nil {
			reportErrorf("simulation error: %s", responseErr.Error())
		}

		encodedResponse := protocol.EncodeJSON(&simulateResponse)
		if outFilename != "" {
			err := writeFile(outFilename, encodedResponse, 0600)
			if err != nil {
				reportErrorf("write file error: %s", err.Error())
			}
		} else {
			fmt.Println(string(encodedResponse))
		}
	},
}

func decodeTxnsFromFile(file string) []transactions.SignedTxn {
	data, err := readFile(file)
	if err != nil {
		reportErrorf(fileReadError, txFilename, err)
	}
	var txgroup []transactions.SignedTxn
	dec := protocol.NewMsgpDecoderBytes(data)
	for {
		var txn transactions.SignedTxn
		err = dec.Decode(&txn)
		if err == io.EOF {
			break
		}
		if err != nil {
			reportErrorf(txDecodeError, txFilename, err)
		}
		txgroup = append(txgroup, txn)
	}
	return txgroup
}

func traceCmdOptionToSimulateTraceConfigModel() simulation.ExecTraceConfig {
	var traceConfig simulation.ExecTraceConfig
	if simulateFullTrace {
		traceConfig = simulation.ExecTraceConfig{
			Enable:  true,
			Stack:   true,
			Scratch: true,
			State:   true,
		}
	}
	traceConfig.Enable = traceConfig.Enable || simulateEnableRequestTrace
	traceConfig.Stack = traceConfig.Stack || simulateStackChange
	traceConfig.Scratch = traceConfig.Scratch || simulateScratchChange
	traceConfig.State = traceConfig.State || simulateAppStateChange

	return traceConfig
}
