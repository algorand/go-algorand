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
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestTxnMerkleProof(t *testing.T) {
	t.Parallel()
	a := require.New(t)

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

	var proof []crypto.Digest
	proofconcat := []byte(proofresp.Proof)
	for len(proofconcat) > 0 {
		var d crypto.Digest
		copy(d[:], proofconcat)
		proof = append(proof, d)
		proofconcat = proofconcat[len(d):]
	}

	blk, err := client.BookkeepingBlock(confirmedTx.ConfirmedRound)
	a.NoError(err)

	merkleNode := []byte(protocol.TxnMerkleLeaf)
	merkleNode = append(merkleNode, txid[:]...)
	merkleNode = append(merkleNode, proofresp.Stibhash...)

	elems := make(map[uint64]crypto.Digest)
	elems[proofresp.Idx] = crypto.Hash(merkleNode)
	err = merklearray.Verify(blk.TxnRoot, elems, proof)
	a.NoError(err)
}
