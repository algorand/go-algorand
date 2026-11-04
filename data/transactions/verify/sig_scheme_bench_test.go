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

package verify

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// BenchmarkSigSchemeWorkset measures what verifying one workset of
// single-transaction payment groups costs on one core, as PaysetGroups does
// for each workset of a block: Ed25519 signatures go through one batch, the
// others are verified one at a time. "sig" is a plain Ed25519 SignedTxn.Sig.
// B/txn is a transaction's size as encoded in a block.
func BenchmarkSigSchemeWorkset(b *testing.B) {
	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)
	ledger := &DummyLedgerForSignature{}
	minFee := config.Consensus[protocol.ConsensusFuture].MinTxnFee
	receiver := basics.Address{1}

	schemes := append([]basics_testing.SigSchemeTest{{Name: "sig"}}, basics_testing.SigSchemeTests...)
	for _, ts := range schemes {
		payset := make([][]transactions.SignedTxn, txnPerWorksetThreshold)
		size := 0
		for i := range payset {
			var stxn transactions.SignedTxn
			if ts.Name == "sig" {
				secrets := crypto.GenerateSignatureSecrets(crypto.Seed{byte(i)})
				stxn = createPayTransaction(minFee, 40, 60, i+1, basics.Address(secrets.SignatureVerifier), receiver).Sign(secrets)
			} else {
				acct := basics_testing.MakeSaltedKeySigTestAccount(b, byte(i), ts.Scheme)
				txn := createPayTransaction(minFee, 40, 60, i+1, acct.Address, receiver)
				sig, err := acct.Signer.Sign(txn)
				require.NoError(b, err)
				stxn = transactions.SignedTxn{Txn: txn, SKsig: transactions.SaltedKeySig{
					Scheme: acct.Scheme, Salt: acct.Salt, PublicKey: acct.PublicKey, Signature: sig,
				}}
			}
			payset[i] = []transactions.SignedTxn{stxn}
			stib, err := blkHdr.EncodeSignedTxn(stxn, transactions.ApplyData{})
			require.NoError(b, err)
			n, err := stib.GetEncodedLength(false)
			require.NoError(b, err)
			size += n
		}

		b.Run(ts.Name, func(b *testing.B) {
			for b.Loop() {
				batch := crypto.MakeBatchVerifierWithHint(len(payset))
				for _, group := range payset {
					_, err := txnGroupBatchPrep(group, &blkHdr, ledger, batch, nil)
					if err != nil {
						b.Fatal(err)
					}
				}
				if err := batch.Verify(); err != nil {
					b.Fatal(err)
				}
			}
			perTxn := float64(b.Elapsed().Nanoseconds()) / float64(b.N*len(payset))
			b.ReportMetric(perTxn, "ns/txn")
			b.ReportMetric(float64(size)/float64(len(payset)), "B/txn")
			b.ReportMetric(perTxn*float64(len(payset))/float64(size), "ns/B")
		})
	}
}
