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
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
)

var (
	addr          string
	msigAddr      string
	noSig         bool
	useLegacyMsig bool
)

func init() {
	clerkCmd.AddCommand(multisigCmd)
	multisigCmd.AddCommand(addSigCmd)
	multisigCmd.AddCommand(mergeSigCmd)
	multisigCmd.AddCommand(signProgramCmd)

	addSigCmd.Flags().StringVarP(&txFilename, "tx", "t", "", "Partially-signed transaction file to add signature to")
	addSigCmd.Flags().StringVarP(&addr, "address", "a", "", "Address of the key to sign with")
	addSigCmd.Flags().BoolVarP(&noSig, "no-sig", "n", false, "Fill in the transaction's multisig field with public keys and threshold information, but don't produce a signature")
	addSigCmd.MarkFlagRequired("tx")

	signProgramCmd.Flags().StringVarP(&programSource, "program", "p", "", "Program source to be compiled and signed")
	signProgramCmd.Flags().StringVarP(&progByteFile, "program-bytes", "P", "", "Program binary to be signed")
	signProgramCmd.Flags().StringVarP(&logicSigFile, "lsig", "L", "", "Partial LogicSig to add signature to")
	signProgramCmd.Flags().StringVarP(&addr, "address", "a", "", "Address of the key to sign with")
	signProgramCmd.Flags().StringVarP(&msigAddr, "msig-address", "A", "", "Multi-Sig Address that signing address is part of")
	signProgramCmd.Flags().StringVarP(&outFilename, "lsig-out", "o", "", "File to write partial Lsig to")
	signProgramCmd.Flags().BoolVar(&useLegacyMsig, "legacy-msig", false, "Use legacy multisig (if not specified, auto-detect consensus params from algod)")
	signProgramCmd.MarkFlagRequired("address")

	mergeSigCmd.Flags().StringVarP(&outFilename, "out", "o", "", "Output file for merged transactions")
	mergeSigCmd.MarkFlagRequired("out")
}

var multisigCmd = &cobra.Command{
	Use:   "multisig",
	Short: "Provides tools working with multisig transactions ",
	Long:  `Create, examine, and add signatures to multisig transactions.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var addSigCmd = &cobra.Command{
	Use:   "sign -t [transaction file] -a [address]",
	Short: "Add a signature to a multisig transaction",
	Long:  `Start a multisig, or add a signature to an existing multisig, for a given transaction.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		data, err := readFile(txFilename)
		if err != nil {
			reportErrorf(fileReadError, txFilename, err)
		}

		// --address and --no-sig are mutually exclusive, since if
		// we're not signing we don't need an address
		if addr == "" && !noSig {
			reportErrorf(addrNoSigError)
		} else if addr != "" && noSig {
			reportErrorf(addrNoSigError)
		}

		dataDir := datadir.EnsureSingleDataDir()
		client := ensureKmdClient(dataDir)
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)

		var outData []byte
		dec := protocol.NewMsgpDecoderBytes(data)
		for {
			var stxn transactions.SignedTxn
			err = dec.Decode(&stxn)
			if err == io.EOF {
				break
			}
			if err != nil {
				reportErrorf(txDecodeError, txFilename, err)
			}

			var msig crypto.MultisigSig
			if noSig {
				multisigInfo, err1 := client.LookupMultisigAccount(wh, stxn.Txn.Sender.String())
				if err1 != nil {
					reportErrorf(msigLookupError, err1)
				}
				msig, err1 = msigInfoToMsig(multisigInfo)
				if err1 != nil {
					reportErrorf(msigParseError, err1)
				}
			} else {
				if stxn.AuthAddr.IsZero() {
					msig, err = client.MultisigSignTransactionWithWallet(wh, pw, stxn.Txn, addr, stxn.Msig)
				} else {
					msig, err = client.MultisigSignTransactionWithWalletAndSigner(wh, pw, stxn.Txn, addr, stxn.Msig, stxn.AuthAddr.GetUserAddress())
				}
				if err != nil {
					reportErrorf(errorSigningTX, err)
				}
			}

			// The following line makes stxn.cachedEncodingLen incorrect, but it's okay because we're just serializing it to a file
			stxn.Msig = msig

			outData = append(outData, protocol.Encode(&stxn)...)
		}

		err = writeFile(txFilename, outData, 0600)
		if err != nil {
			reportErrorf(fileWriteError, txFilename, err)
		}
	},
}

var signProgramCmd = &cobra.Command{
	Use:   "signprogram -a [address]",
	Short: "Add a signature to a multisig LogicSig",
	Long:  `Start a multisig LogicSig, or add a signature to an existing multisig, for a given program.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := datadir.EnsureSingleDataDir()
		client := ensureKmdClient(dataDir)
		wh, pw := ensureWalletHandleMaybePassword(dataDir, walletName, true)
		var program []byte
		outname := outFilename
		var lsig transactions.LogicSig
		gotPartial := false
		if programSource != "" {
			if logicSigFile != "" || progByteFile != "" {
				reportErrorf(multisigProgramCollision)
			}
			text, err := readFile(programSource)
			if err != nil {
				reportErrorf(fileReadError, programSource, err)
			}
			ops, err := logic.AssembleString(string(text))
			if err != nil {
				ops.ReportMultipleErrors(programSource, os.Stderr)
				reportErrorf("%s: %s", programSource, err)
			}
			if outname == "" {
				outname = fmt.Sprintf("%s.lsig", programSource)
			}
			lsig.Logic = ops.Program
			program = ops.Program
		} else if logicSigFile != "" {
			if progByteFile != "" {
				reportErrorf(multisigProgramCollision)
			}
			var err error
			program, err = readFile(logicSigFile)
			if err != nil {
				reportErrorf(fileReadError, logicSigFile, err)
			}
			err = protocol.Decode(program, &lsig)
			if err != nil {
				reportErrorf("%s: %s", logicSigFile, err)
			}
			program = lsig.Logic
			if outname == "" {
				outname = logicSigFile
			}
			gotPartial = true
		} else if progByteFile != "" {
			var err error
			program, err = readFile(progByteFile)
			if err != nil {
				reportErrorf(fileReadError, progByteFile, err)
			}
			lsig = transactions.LogicSig{}
			if outname == "" {
				outname = fmt.Sprintf("%s.lsig", progByteFile)
			}
			lsig.Logic = program
		}

		if !cmd.Flags().Changed("legacy-msig") { // if not specified, auto-detect from consensus params
			params, err := client.SuggestedParams()
			if err == nil {
				if cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]; ok {
					useLegacyMsig = !cparams.LogicSigLMsig
				}
			}
		}

		// Get or create partial multisig from appropriate field
		var partial crypto.MultisigSig
		if gotPartial {
			if useLegacyMsig {
				if !lsig.LMsig.Blank() {
					reportErrorf("LogicSig file contains LMsig field, but --legacy-msig=true is set, which uses Msig. Specify --legacy-msig=false to use LMsig, or provide a LogicSig file with Msig field")
				}
				partial = lsig.Msig
			} else {
				if !lsig.Msig.Blank() {
					reportErrorf("LogicSig file contains Msig field, but --legacy-msig=false is set, which uses LMsig. Specify --legacy-msig=true to use Msig, or provide a LogicSig file with LMsig field")
				}
				partial = lsig.LMsig
			}
		} else {
			if msigAddr == "" {
				reportErrorf("--msig-address/-A required when partial LogicSig not available")
			}
			multisigInfo, err := client.LookupMultisigAccount(wh, msigAddr)
			if err != nil {
				reportErrorf(msigLookupError, err)
			}
			partial, err = msigInfoToMsig(multisigInfo)
			if err != nil {
				reportErrorf(msigParseError, err)
			}
		}

		msig, err := client.MultisigSignProgramWithWallet(wh, pw, program, addr, partial, useLegacyMsig)
		if err != nil {
			reportErrorf(errorSigningTX, err)
		}

		if useLegacyMsig {
			lsig.Msig = msig
			lsig.LMsig = crypto.MultisigSig{}
		} else {
			lsig.Msig = crypto.MultisigSig{}
			lsig.LMsig = msig
		}
		lsigblob := protocol.Encode(&lsig)
		err = writeFile(outname, lsigblob, 0600)
		if err != nil {
			reportErrorf("%s: %s", outname, err)
		}
	},
}

var mergeSigCmd = &cobra.Command{
	Use:   "merge -o [merged transaction file] [input file 1] [input file 2]...",
	Short: "Merge multisig signatures on transactions",
	Long:  `Combine multiple partially-signed multisig transactions, and write out transactions with a single merged multisig signature.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			reportErrorf(txNoFilesError)
		}

		var txnLists [][]transactions.SignedTxn
		for _, arg := range args {
			data, err := os.ReadFile(arg)
			if err != nil {
				reportErrorf(fileReadError, arg, err)
			}

			dec := protocol.NewMsgpDecoderBytes(data)
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
			mergedData = append(mergedData, protocol.Encode(&txn)...)
		}

		err := writeFile(outFilename, mergedData, 0600)
		if err != nil {
			reportErrorf(fileWriteError, outFilename, err)
		}
	},
}

func msigInfoToMsig(multisigInfo libgoal.MultisigInfo) (msig crypto.MultisigSig, err error) {
	var pks []crypto.PublicKey
	for _, pk := range multisigInfo.PKs {
		var addr basics.Address
		addr, err = basics.UnmarshalChecksumAddress(pk)
		if err != nil {
			return
		}
		pks = append(pks, crypto.PublicKey(addr))
	}
	msig = crypto.MultisigPreimageFromPKs(multisigInfo.Version, multisigInfo.Threshold, pks)
	return
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

	stxn.Msig, _ = msigInfoToMsig(multisigInfo)
	return stxn
}
