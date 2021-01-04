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
	"encoding/base32"
	"encoding/base64"
	"io/ioutil"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"

	"github.com/spf13/cobra"
)

var (
	keyFilename     string
	signerAcct      string
	lsigTxnFilename string
	contractAddr    string
	signTxID        bool
	dataFile        string
	datab64         string
	datab32         string
	setLsigArg      int
)

func init() {
	clerkCmd.AddCommand(tealsignCmd)

	tealsignCmd.Flags().StringVar(&keyFilename, "keyfile", "", "algokey private key file to sign with")
	tealsignCmd.Flags().StringVar(&signerAcct, "account", "", "Address of account to sign with")
	tealsignCmd.Flags().StringVar(&lsigTxnFilename, "lsig-txn", "", "Transaction with logicsig to sign data for")
	tealsignCmd.Flags().StringVar(&contractAddr, "contract-addr", "", "Contract address to sign data for. not necessary if --lsig-txn is provided")
	tealsignCmd.Flags().BoolVar(&signTxID, "sign-txid", false, "Use the txid of --lsig-txn as the data to sign")
	tealsignCmd.Flags().StringVar(&dataFile, "data-file", "", "Data file to sign")
	tealsignCmd.Flags().StringVar(&datab64, "data-b64", "", "base64 data to sign")
	tealsignCmd.Flags().StringVar(&datab32, "data-b32", "", "base32 data to sign")
	tealsignCmd.Flags().IntVar(&setLsigArg, "set-lsig-arg-idx", -1, "If --lsig-txn is also specified, set the lsig arg at this index to the raw signature bytes. Overwrites any existing argument at this index. Updates --lsig-txn file in place. nil args will be appended until index is valid.")
}

var tealsignCmd = &cobra.Command{
	Use:   "tealsign",
	Short: "Sign data to be verified in a TEAL program",
	Long: `Sign data to be verified in a TEAL program.

Data verified by the ed25519verify TEAL opcode must be domain separated. As part of this process, the signed payload includes the hash of the program logic. This hash must be specified. To do this, provide a transaction whose logic sig contains the program via --lsig-txn, or provide a contract address directly with --contract-addr. These options are mutually exclusive.

Next, you must specify the data to be signed. When using --lsig-txn, you can use the --sign-txid flag to sign that transaction's txid. Alternatively, arbitrary data can be signed with the --data-file, --data-b64, or --data-b32 options. These options are mutually exclusive.

The base64 encoding of the signature will always be printed to stdout. Optionally, when using --lsig-txn, you may specify that the signature be used as a TEAL argument for that transaction. Specify the argument index with the --set-lsig-arg-idx flag. The --lsig-txn file will be updated in place, and any existing argument at that index will be overwritten.`,
	Args: validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		/*
		 * First, fetch the key for signing
		 */

		if keyFilename != "" && signerAcct != "" {
			reportErrorf(tealsignMutKeyArgs)
		}

		if keyFilename == "" && signerAcct == "" {
			reportErrorf(tealsignMutKeyArgs)
		}

		var kdata []byte
		var err error
		if keyFilename != "" {
			kdata, err = ioutil.ReadFile(keyFilename)
			if err != nil {
				reportErrorf(tealsignKeyfileFail, err)
			}
		}

		// --account not yet supported, coming in another PR
		// (need to add kmd support for signing logicsig data)
		if signerAcct != "" {
			reportErrorf(tealsignNoWithAcct)
		}

		// Create signature secrets from the seed
		var seed crypto.Seed
		copy(seed[:], kdata)
		sec := crypto.GenerateSignatureSecrets(seed)

		/*
		 * Next, fetch the hash of the program for use in the domain
		 * separated signature payload
		 */

		var lsigHashArgs int
		if lsigTxnFilename != "" {
			lsigHashArgs++
		}
		if contractAddr != "" {
			lsigHashArgs++
		}

		// Ensure there is one unambiguous source of program hash
		if lsigHashArgs != 1 {
			reportErrorf(tealsignMutLsigArgs)
		}

		var progHash crypto.Digest
		var stxn transactions.SignedTxn
		if lsigTxnFilename != "" {
			// If passed a SignedTxn with a logic sig, compute
			// the hash of the program within the logic sig
			stxnBytes, err := ioutil.ReadFile(lsigTxnFilename)
			if err != nil {
				reportErrorf(fileReadError, lsigTxnFilename, err)
			}

			err = protocol.Decode(stxnBytes, &stxn)
			if err != nil {
				reportErrorf(txDecodeError, lsigTxnFilename, err)
			}

			// Ensure signed transaction has a logic sig with a
			// program
			if len(stxn.Lsig.Logic) == 0 {
				reportErrorf(tealsignEmptyLogic)
			}

			progHash = crypto.HashObj(logic.Program(stxn.Lsig.Logic))
		} else {
			// Otherwise, the contract address is the logic hash
			parsedAddr, err := basics.UnmarshalChecksumAddress(contractAddr)
			if err != nil {
				reportErrorf(tealsignParseAddr, err)
			}

			// Copy parsed address as program hash
			copy(progHash[:], parsedAddr[:])
		}

		/*
		 * Next, fetch the data to sign
		 */

		var dataArgs int
		var dataToSign []byte

		if dataFile != "" {
			dataToSign, err = ioutil.ReadFile(dataFile)
			if err != nil {
				reportErrorf(tealsignParseData, err)
			}
			dataArgs++
		}
		if datab64 != "" {
			dataToSign, err = base64.StdEncoding.DecodeString(datab64)
			if err != nil {
				reportErrorf(tealsignParseb64, err)
			}
			dataArgs++
		}
		if datab32 != "" {
			dataToSign, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(datab32)
			if err != nil {
				reportErrorf(tealsignParseb32, err)
			}
			dataArgs++
		}
		if signTxID {
			if lsigTxnFilename == "" {
				reportErrorf(tealsignTxIDLsigReq)
			}
			txid := stxn.Txn.ID()
			dataToSign = txid[:]
			dataArgs++
		}

		// Ensure there is one unambiguous source of data
		if dataArgs != 1 {
			reportErrorf(tealsignDataReq)
		}

		/*
		 * Sign the payload
		 */

		signature := sec.Sign(logic.Msg{
			ProgramHash: progHash,
			Data:        dataToSign,
		})

		/*
		 * If requested, fill in logic sig arg
		 */

		if setLsigArg >= 0 {
			if lsigTxnFilename == "" {
				reportErrorf(tealsignSetArgLsigReq)
			}
			if setLsigArg > transactions.EvalMaxArgs-1 {
				reportErrorf(tealsignTooManyArg, transactions.EvalMaxArgs)
			}
			for len(stxn.Lsig.Args) < setLsigArg+1 {
				stxn.Lsig.Args = append(stxn.Lsig.Args, nil)
			}
			stxn.Lsig.Args[setLsigArg] = signature[:]

			// Write out the modified stxn
			err = writeFile(lsigTxnFilename, protocol.Encode(&stxn), 0600)
			if err != nil {
				reportErrorf(fileWriteError, lsigTxnFilename, err)
			}
			reportInfof(tealsignInfoWroteSig, lsigTxnFilename, setLsigArg)
		}

		// Always print signature to stdout
		signatureb64 := base64.StdEncoding.EncodeToString(signature[:])
		reportInfof(tealsignInfoSig, signatureb64)
	},
}
