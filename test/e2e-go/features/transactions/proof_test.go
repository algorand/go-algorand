// Copyright (C) 2019-2022 Algorand, Inc.
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
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
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
	confirmedTx, err := fixture.WaitForConfirmedTxn(status.LastRound+10, baseAcct, txid.String())
	a.NoError(err)

	blk, err := client.BookkeepingBlock(confirmedTx.ConfirmedRound)
	a.NoError(err)

	proofresp, err := client.TxnProof(txid.String(), confirmedTx.ConfirmedRound, crypto.Sha512_256)
	a.NoError(err)

	proofrespSHA256, err := client.TxnProof(txid.String(), confirmedTx.ConfirmedRound, crypto.Sha256)
	a.NoError(err)

	generateProof := func(h crypto.HashType, prfRsp generated.ProofResponse) (p merklearray.Proof) {
		p.HashFactory = crypto.HashFactory{HashType: h}
		p.TreeDepth = uint8(prfRsp.Treedepth)
		a.NotEqual(p.TreeDepth, 0)
		proofconcat := prfRsp.Proof
		for len(proofconcat) > 0 {
			var d crypto.Digest
			copy(d[:], proofconcat)
			p.Path = append(p.Path, d[:])
			proofconcat = proofconcat[len(d):]
		}
		return
	}

	proof := generateProof(crypto.Sha512_256, proofresp)
	proofSHA256 := generateProof(crypto.Sha256, proofrespSHA256)

	element := TxnMerkleElemRaw{Txn: crypto.Digest(txid)}
	copy(element.Stib[:], proofresp.Stibhash[:])

	elems := make(map[uint64]crypto.Hashable)

	elems[proofresp.Idx] = &element
	err = merklearray.Verify(blk.TxnRoot.DigestSha512_256.ToSlice(), elems, &proof)
	if err != nil {
		t.Logf("blk.TxnRoot : %v \nproof path %v \ndepth: %d \nStibhash %v\nIndex: %d", blk.TxnRoot.DigestSha512_256.ToSlice(), proof.Path, proof.TreeDepth, proofresp.Stibhash, proofresp.Idx)
		a.NoError(err)
	}

	element = TxnMerkleElemRaw{Txn: crypto.Digest(txidSHA256)}
	copy(element.Stib[:], proofrespSHA256.Stibhash[:])

	elems = make(map[uint64]crypto.Hashable)

	elems[proofrespSHA256.Idx] = &element
	err = merklearray.VerifyVectorCommitment(blk.TxnRoot.DigestSha256.ToSlice(), elems, &proofSHA256)
	if err != nil {
		t.Logf("blk.TxnRoot : %v \nproof path %v \ndepth: %d \nStibhash %v\nIndex: %d", blk.TxnRoot.DigestSha256.ToSlice(), proofSHA256.Path, proofSHA256.TreeDepth, proofrespSHA256.Stibhash, proofrespSHA256.Idx)
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
	confirmedTx, err := fixture.WaitForConfirmedTxn(status.LastRound+10, baseAcct, txid.String())
	a.NoError(err)

	blk, err := client.BookkeepingBlock(confirmedTx.ConfirmedRound)
	a.NoError(err)
	proto := config.Consensus[blk.CurrentProtocol]
	a.False(proto.EnableSHA256TxnRootHeader)

	a.NotEqual(crypto.Digest{}, blk.TxnRoot.DigestSha512_256)
	a.Equal(crypto.Digest{}, blk.TxnRoot.DigestSha256) // should be empty since not yet supported
}
