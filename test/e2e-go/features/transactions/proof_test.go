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

package transactions

import (
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TxnMerkleElemRaw this struct helps creates a hashable struct from the bytes
type TxnMerkleElemRaw struct {
	Txn  []byte // txn id
	Stib []byte // hash value of transactions.SignedTxnInBlock
}

func txnMerkleToRaw(txid []byte, stib []byte) []byte {
	buf := make([]byte, 0, 2*crypto.DigestSize)
	buf = append(buf, txid...)
	return append(buf, stib...)
}

// ToBeHashed implements the crypto.Hashable interface.
func (tme *TxnMerkleElemRaw) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TxnMerkleLeaf, txnMerkleToRaw(tme.Txn, tme.Stib)
}

func TestTxnMerkleProof(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "OneNodeFuture.json"))
	defer fixture.Shutdown()
	client := fixture.LibGoalClient

	// We will create three new accounts, transfer some amount of money into
	// the first account, and then transfer a smaller amount to the second
	// account while closing out the rest into the third.

	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	baseAcct := accountList[0].Address

	walletHandle, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	acct0, err := client.GenerateAddress(walletHandle)
	a.NoError(err)

	status, err := client.Status()
	a.NoError(err)

	// Transfer some money to acct0, as well as other random accounts to
	// fill up the Merkle tree with more than one element.
	for i := 0; i < 10; i++ {
		accti, err := client.GenerateAddress(walletHandle)
		a.NoError(err)

		_, err = client.SendPaymentFromUnencryptedWallet(baseAcct, accti, 1000, 10000000, nil)
		a.NoError(err)
	}

	tx, err := client.SendPaymentFromUnencryptedWallet(baseAcct, acct0, 1000, 10000000, nil)
	a.NoError(err)

	for i := 0; i < 10; i++ {
		accti, err := client.GenerateAddress(walletHandle)
		a.NoError(err)

		_, err = client.SendPaymentFromUnencryptedWallet(baseAcct, accti, 1000, 10000000, nil)
		a.NoError(err)
	}

	txid := tx.ID()
	confirmedTx, err := fixture.WaitForConfirmedTxn(status.LastRound+10, baseAcct, txid.String())
	a.NoError(err)

	proofresp, err := client.TxnProof(txid.String(), confirmedTx.ConfirmedRound)
	a.NoError(err)

	var proof merklearray.Proof
	proof.HashFactory = crypto.HashFactory{HashType: crypto.Sha512_256}
	proofconcat := []byte(proofresp.Proof)
	for len(proofconcat) > 0 {
		var d crypto.Digest
		copy(d[:], proofconcat)
		proof.Path = append(proof.Path, d[:])
		proofconcat = proofconcat[len(d):]
	}

	blk, err := client.BookkeepingBlock(confirmedTx.ConfirmedRound)
	a.NoError(err)

	element := TxnMerkleElemRaw{Txn: txid[:], Stib: proofresp.Stibhash}

	elems := make(map[uint64]crypto.Hashable)

	elems[proofresp.Idx] = &element
	err = merklearray.Verify(blk.TxnRoot.ToSlice(), elems, &proof)
	a.NoError(err)
}
