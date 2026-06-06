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
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var allowRekey bool

type rekeyTxnInfo struct {
	Index        int
	Sender       basics.Address
	RekeyTo      basics.Address
	Type         protocol.TxType
	Group        crypto.Digest
	AssetOptIn   bool
	SameGroupKey string
}

type rekeyScanReport struct {
	Rekeys                []rekeyTxnInfo
	HasAssetOptInAndRekey bool
}

func addAllowRekeyFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&allowRekey, "allow-rekey", false, "Acknowledge and allow signing a transaction that changes an account's spending authority")
}

func decodeSignedTxns(data []byte) ([]transactions.SignedTxn, error) {
	var txns []transactions.SignedTxn
	dec := protocol.NewMsgpDecoderBytes(data)
	for {
		var stxn transactions.SignedTxn
		err := dec.Decode(&stxn)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		txns = append(txns, stxn)
	}
	return txns, nil
}

func validateSafeToSign(stxns []transactions.SignedTxn, source string) error {
	report := scanForRekey(stxns)
	if len(report.Rekeys) == 0 || allowRekey {
		return nil
	}

	var details []string
	for _, txn := range report.Rekeys {
		detail := fmt.Sprintf("txn[%d] %s sender=%s rekey-to=%s", txn.Index, txn.Type, txn.Sender.String(), txn.RekeyTo.String())
		if txn.AssetOptIn {
			detail += " asset-opt-in"
		}
		details = append(details, detail)
	}

	reason := "contains rekeyed transactions"
	if report.HasAssetOptInAndRekey {
		reason = "contains an asset opt-in grouped with rekeying"
	}

	return fmt.Errorf("refusing to sign %s because it %s. Re-run with --allow-rekey only after verifying intent. %s", source, reason, strings.Join(details, "; "))
}

func scanForRekey(stxns []transactions.SignedTxn) rekeyScanReport {
	report := rekeyScanReport{}
	groupHasRekey := make(map[string]bool)
	groupHasAssetOptIn := make(map[string]bool)

	for idx, stxn := range stxns {
		groupKey := rekeyGroupKey(stxn.Txn.Group, idx)
		if isAssetOptInTxn(stxn.Txn) {
			groupHasAssetOptIn[groupKey] = true
		}
		if stxn.Txn.RekeyTo == (basics.Address{}) {
			continue
		}

		groupHasRekey[groupKey] = true
		report.Rekeys = append(report.Rekeys, rekeyTxnInfo{
			Index:        idx,
			Sender:       stxn.Txn.Sender,
			RekeyTo:      stxn.Txn.RekeyTo,
			Type:         stxn.Txn.Type,
			Group:        stxn.Txn.Group,
			AssetOptIn:   isAssetOptInTxn(stxn.Txn),
			SameGroupKey: groupKey,
		})
	}

	for _, txn := range report.Rekeys {
		if groupHasAssetOptIn[txn.SameGroupKey] && groupHasRekey[txn.SameGroupKey] {
			report.HasAssetOptInAndRekey = true
			break
		}
	}

	return report
}

func rekeyGroupKey(group crypto.Digest, index int) string {
	if group == (crypto.Digest{}) {
		return fmt.Sprintf("ungrouped-%d", index)
	}
	return group.String()
}

func isAssetOptInTxn(txn transactions.Transaction) bool {
	return txn.Type == protocol.AssetTransferTx &&
		txn.XferAsset != 0 &&
		txn.AssetAmount == 0 &&
		txn.AssetSender == (basics.Address{}) &&
		txn.AssetReceiver == txn.Sender &&
		txn.AssetCloseTo == (basics.Address{})
}
