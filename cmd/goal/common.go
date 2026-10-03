// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
)

const (
	stdoutFilenameValue = "-"
	stdinFileNameValue  = "-"
)

// validateNoPosArgsFn is a reusable cobra positional argument validation function
// for generating proper error messages when commands see unexpected arguments when they expect no args.
// We don't use cobra.NoArgs directly, in case we want to customize behavior later.
var validateNoPosArgsFn = cobra.NoArgs

// transaction validity period margins
var firstValid basics.Round
var lastValid basics.Round

// numValidRounds specifies validity period for a transaction and used to calculate last valid round
var numValidRounds basics.Round // also used in account and asset

var (
	fee             uint64
	outFilename     string
	sign            bool
	noteBase64      string
	noteText        string
	lease           string
	noWaitAfterSend bool
	rekeyToAddress  string
)

func addTxnFlags(cmd *cobra.Command) {
	cmd.Flags().Uint64Var(&fee, "fee", 0, "The transaction fee (automatically determined by default), in microAlgos")
	cmd.Flags().Uint64Var((*uint64)(&firstValid), "firstvalid", 0, "The first round where the transaction may be committed to the ledger")
	cmd.Flags().Uint64Var((*uint64)(&numValidRounds), "validrounds", 0, "The number of rounds for which the transaction will be valid")
	cmd.Flags().Uint64Var((*uint64)(&lastValid), "lastvalid", 0, "The last round where the transaction may be committed to the ledger")
	cmd.Flags().StringVarP(&outFilename, "out", "o", "", "Write transaction to this file")
	cmd.Flags().BoolVarP(&sign, "sign", "s", false, "Use with -o to indicate that the dumped transaction should be signed")
	cmd.Flags().StringVar(&noteBase64, "noteb64", "", "Note (URL-base64 encoded)")
	cmd.Flags().StringVarP(&noteText, "note", "n", "", "Note text (ignored if --noteb64 used also)")
	cmd.Flags().StringVarP(&lease, "lease", "x", "", "Lease value (base64, optional): no transaction may also acquire this lease until lastvalid")
	cmd.Flags().BoolVarP(&noWaitAfterSend, "no-wait", "N", false, "Don't wait for transaction to commit")
	cmd.Flags().StringVarP(&signerAddress, "signer", "S", "", "Address of key to sign with, if different from transaction \"from\" address due to rekeying")
	cmd.Flags().StringVar(&rekeyToAddress, "rekey-to", "", "Rekey account to the given spending key/address. (Future transactions from this account will need to be signed with the new key.)")
}

func parseRekey(rekeyToAddress string) basics.Address {
	if rekeyToAddress == "" {
		return basics.Address{}
	}
	rekeyTo, err := basics.UnmarshalChecksumAddress(rekeyToAddress)
	if err != nil {
		reportErrorln(err)
	}
	return rekeyTo
}

// applyFeeAndTip applies explicit fee and tip flags to a transaction.
// If the user explicitly provided --fee (including --fee=0 for fee-pooling in tx groups),
// it overrides any default or suggested fee that was computed during transaction creation.
// If a --tip flag is present on the command and set, it adds the tip to the transaction fee.
func applyFeeAndTip(tx *transactions.Transaction, cmd *cobra.Command, client libgoal.Client, explicitFee ...uint64) {
	if cmd != nil && cmd.Flags().Lookup("fee") != nil && cmd.Flags().Changed("fee") {
		f, err := cmd.Flags().GetUint64("fee")
		if err == nil {
			tx.Fee = basics.MicroAlgos{Raw: f}
		} else if len(explicitFee) > 0 {
			tx.Fee = basics.MicroAlgos{Raw: explicitFee[0]}
		}
	} else if len(explicitFee) > 0 && explicitFee[0] != 0 {
		tx.Fee = basics.MicroAlgos{Raw: explicitFee[0]}
	}

	if cmd != nil && cmd.Flags().Lookup("tip") != nil && cmd.Flags().Changed("tip") {
		tipVal, err := cmd.Flags().GetUint64("tip")
		if err == nil {
			tx.Fee = tx.Fee.AddSaturate(basics.MicroAlgos{Raw: tipVal})
		}
	}
}

