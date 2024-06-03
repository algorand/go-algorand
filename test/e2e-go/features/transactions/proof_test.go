// Copyright (C) 2019-2024 Algorand, Inc.
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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TxnMerkleElemRaw this struct helps creates a hashable struct from the bytes
type TxnMerkleElemRaw struct {
	Txn  crypto.Digest // txn id
	Stib crypto.Digest // hash value of transactions.SignedTxnInBlock
}

func txnMerkleToRaw(txid [crypto.DigestSize]byte, stib [crypto.DigestSize]byte) (buf []byte) {
	buf = make([]byte, 2*crypto.DigestSize)
	copy(buf[:], txid[:])
	copy(buf[crypto.DigestSize:], stib[:])
	return
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
	// we do not want to have a full tree in order the catch an empty element edge case
	for i := 0; i < 5; i++ {
		accti, err := client.GenerateAddress(walletHandle)
		a.NoError(err)

		_, err = client.SendPaymentFromUnencryptedWallet(baseAcct, accti, 1000, 10000000, nil)
		a.NoError(err)
	}

	tx, err := client.SendPaymentFromUnencryptedWallet(baseAcct, acct0, 1000, 10000000, nil)
	a.NoError(err)

	txid := tx.ID()
	txidSHA256 := tx.IDSha256() // only used for verification
	confirmedTx, err := fixture.WaitForConfirmedTxn(status.LastRound+10, txid.String())
	a.NoError(err)
	a.NotNil(confirmedTx.ConfirmedRound)

	blk, err := client.BookkeepingBlock(*confirmedTx.ConfirmedRound)
	a.NoError(err)

	proofresp, proof, err := fixture.TransactionProof(txid.String(), *confirmedTx.ConfirmedRound, crypto.Sha512_256)
	a.NoError(err)

	proofrespSHA256, proofSHA256, err := fixture.TransactionProof(txid.String(), *confirmedTx.ConfirmedRound, crypto.Sha256)
	a.NoError(err)

	element := TxnMerkleElemRaw{Txn: crypto.Digest(txid)}
	copy(element.Stib[:], proofresp.Stibhash[:])

	elems := make(map[uint64]crypto.Hashable)

	elems[proofresp.Idx] = &element
	err = merklearray.Verify(blk.TxnCommitments.NativeSha512_256Commitment.ToSlice(), elems, proof.ToProof())
	if err != nil {
		t.Logf("blk.TxnCommitments : %v \nproof path %v \ndepth: %d \nStibhash %v\nIndex: %d", blk.TxnCommitments.NativeSha512_256Commitment.ToSlice(), proof.Path, proof.TreeDepth, proofresp.Stibhash, proofresp.Idx)
		a.NoError(err)
	}

	element = TxnMerkleElemRaw{Txn: crypto.Digest(txidSHA256)}
	copy(element.Stib[:], proofrespSHA256.Stibhash[:])

	elems = make(map[uint64]crypto.Hashable)

	elems[proofrespSHA256.Idx] = &element
	err = merklearray.VerifyVectorCommitment(blk.TxnCommitments.Sha256Commitment.ToSlice(), elems, proofSHA256.ToProof())
	if err != nil {
		t.Logf("blk.TxnCommitments : %v \nproof path %v \ndepth: %d \nStibhash %v\nIndex: %d", blk.TxnCommitments.Sha256Commitment.ToSlice(), proofSHA256.Path, proofSHA256.TreeDepth, proofrespSHA256.Stibhash, proofrespSHA256.Idx)
		a.NoError(err)
	}
}

// make sure transaction proof SHA256 does not exist in current consensus version (until we upgrade)
func TestTxnMerkleProofSHA256(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachV32.json"))
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
	// we do not want to have a full tree in order the catch an empty element edge case
	for i := 0; i < 5; i++ {
		accti, err := client.GenerateAddress(walletHandle)
		a.NoError(err)

		_, err = client.SendPaymentFromUnencryptedWallet(baseAcct, accti, 1000, 10000000, nil)
		a.NoError(err)
	}

	tx, err := client.SendPaymentFromUnencryptedWallet(baseAcct, acct0, 1000, 10000000, nil)
	a.NoError(err)

	txid := tx.ID()
	confirmedTx, err := fixture.WaitForConfirmedTxn(status.LastRound+10, txid.String())
	a.NoError(err)
	a.NotNil(confirmedTx.ConfirmedRound)

	blk, err := client.BookkeepingBlock(*confirmedTx.ConfirmedRound)
	a.NoError(err)
	proto := config.Consensus[blk.CurrentProtocol]
	a.False(proto.EnableSHA256TxnCommitmentHeader)

	a.NotEqual(crypto.Digest{}, blk.TxnCommitments.NativeSha512_256Commitment)
	a.Equal(crypto.Digest{}, blk.TxnCommitments.Sha256Commitment) // should be empty since not yet supported
}
