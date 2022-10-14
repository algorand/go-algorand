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

package verify

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
)

var feeSink = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var blockHeader = bookkeeping.BlockHeader{
	RewardsState: bookkeeping.RewardsState{
		FeeSink:     feeSink,
		RewardsPool: poolAddr,
	},
	UpgradeState: bookkeeping.UpgradeState{
		CurrentProtocol: protocol.ConsensusCurrentVersion,
	},
}

var spec = transactions.SpecialAddresses{
	FeeSink:     feeSink,
	RewardsPool: poolAddr,
}

func verifyTxn(s *transactions.SignedTxn, txnIdx int, groupCtx *GroupContext) error {
	batchVerifier := crypto.MakeBatchVerifier()

	if err := txnBatchPrep(s, txnIdx, groupCtx, batchVerifier); err != nil {
		return err
	}
	return batchVerifier.Verify()
}

type DummyLedgerForSignature struct {
}

func (d *DummyLedgerForSignature) BlockHdrCached(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{
		Round:       50,
		GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
		RewardsState: bookkeeping.RewardsState{
			FeeSink:     feeSink,
			RewardsPool: poolAddr,
		},
	}, nil
}

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func generateMultiSigTxn(numTxs, numAccs int, blockRound basics.Round, t *testing.T) ([]transactions.Transaction, []transactions.SignedTxn, []*crypto.SignatureSecrets, []basics.Address) {
	secrets, addresses, pks, multiAddress := generateMultiSigAccounts(t, numAccs)

	numMultiSigAcct := len(multiAddress)
	txs := make([]transactions.Transaction, numTxs)
	signed := make([]transactions.SignedTxn, numTxs)

	var iss, exp int
	u := uint64(0)

	for i := 0; i < numTxs; i++ {
		s := rand.Intn(numMultiSigAcct)
		r := rand.Intn(numMultiSigAcct)
		a := rand.Intn(1000)
		f := config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee + uint64(rand.Intn(10)) + u
		if blockRound == 0 {
			iss = 50 + rand.Intn(30)
			exp = iss + 10
		} else {
			iss = int(blockRound) / 2
			exp = int(blockRound) + rand.Intn(30)
		}

		txs[i] = transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      multiAddress[s],
				Fee:         basics.MicroAlgos{Raw: f},
				FirstValid:  basics.Round(iss),
				LastValid:   basics.Round(exp),
				GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: multiAddress[r],
				Amount:   basics.MicroAlgos{Raw: uint64(a)},
			},
		}
		signed[i].Txn = txs[i]

		// create multi sig that 2 out of 3 has signed the txn
		var sigs [2]crypto.MultisigSig
		for j := 0; j < 2; j++ {
			msig, err := crypto.MultisigSign(txs[i], crypto.Digest(multiAddress[s]), 1, 2, pks[3*s:3*s+3], *secrets[3*s+j])
			require.NoError(t, err)
			sigs[j] = msig
		}
		msig, err := crypto.MultisigAssemble(sigs[:])
		require.NoError(t, err)
		signed[i].Msig = msig
		u += 100
	}

	return txs, signed, secrets, addresses
}

func generateMultiSigAccounts(t *testing.T, numAccs int) ([]*crypto.SignatureSecrets, []basics.Address, []crypto.PublicKey, []basics.Address) {
	require.Equal(t, numAccs%3, 0, "numAccs should be multiple of 3 to create multiaccounts")

	numMultiSigAcct := numAccs / 3
	secrets, addresses, pks := generateAccounts(numAccs)

	multiAddress := make([]basics.Address, numMultiSigAcct)

	// create multiAccounts
	for i := 0; i < numAccs; i += 3 {
		multiSigAdd, err := crypto.MultisigAddrGen(1, 2, pks[i:i+3])
		require.NoError(t, err)
		multiAddress[i/3] = basics.Address(multiSigAdd)
	}
	return secrets, addresses, pks, multiAddress
}

func generateAccounts(numAccs int) ([]*crypto.SignatureSecrets, []basics.Address, []crypto.PublicKey) {
	secrets := make([]*crypto.SignatureSecrets, numAccs)
	addresses := make([]basics.Address, numAccs)
	pks := make([]crypto.PublicKey, numAccs)

	for i := 0; i < numAccs; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
		pks[i] = secret.SignatureVerifier
	}
	return secrets, addresses, pks
}

func generateTestObjects(numTxs, numAccs int, blockRound basics.Round) ([]transactions.Transaction, []transactions.SignedTxn, []*crypto.SignatureSecrets, []basics.Address) {
	txs := make([]transactions.Transaction, numTxs)
	signed := make([]transactions.SignedTxn, numTxs)
	secrets, addresses, _ := generateAccounts(numAccs)

	var iss, exp int
	u := uint64(0)
	for i := 0; i < numTxs; i++ {
		s := rand.Intn(numAccs)
		r := rand.Intn(numAccs)
		a := rand.Intn(1000)
		f := config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee + uint64(rand.Intn(10)) + u
		if blockRound == 0 {
			iss = 50 + rand.Intn(30)
			exp = iss + 10
		} else {
			iss = int(blockRound) / 2
			exp = int(blockRound) + rand.Intn(30)
		}

		txs[i] = transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      addresses[s],
				Fee:         basics.MicroAlgos{Raw: f},
				FirstValid:  basics.Round(iss),
				LastValid:   basics.Round(exp),
				GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: addresses[r],
				Amount:   basics.MicroAlgos{Raw: uint64(a)},
			},
		}
		signed[i] = txs[i].Sign(secrets[s])
		u += 100
	}

	return txs, signed, secrets, addresses
}

func TestSignedPayment(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	payments, stxns, secrets, addrs := generateTestObjects(1, 1, 0)
	payment, stxn, secret, addr := payments[0], stxns[0], secrets[0], addrs[0]

	groupCtx, err := PrepareGroupContext(stxns, blockHeader, nil)
	require.NoError(t, err)
	require.NoError(t, payment.WellFormed(spec, proto), "generateTestObjects generated an invalid payment")
	require.NoError(t, verifyTxn(&stxn, 0, groupCtx), "generateTestObjects generated a bad signedtxn")

	stxn2 := payment.Sign(secret)
	require.Equal(t, stxn2.Sig, stxn.Sig, "got two different signatures for the same transaction (our signing function is deterministic)")

	stxn2.MessUpSigForTesting()
	require.Equal(t, stxn.ID(), stxn2.ID(), "changing sig caused txid to change")
	require.Error(t, verifyTxn(&stxn2, 0, groupCtx), "verify succeeded with bad sig")

	require.True(t, crypto.SignatureVerifier(addr).Verify(payment, stxn.Sig), "signature on the transaction is not the signature of the hash of the transaction under the spender's key")
}

func TestTxnValidationEncodeDecode(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signed, _, _ := generateTestObjects(100, 50, 0)

	for _, txn := range signed {
		groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{txn}, blockHeader, nil)
		require.NoError(t, err)
		if verifyTxn(&txn, 0, groupCtx) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}

		x := protocol.Encode(&txn)
		var signedTx transactions.SignedTxn
		protocol.Decode(x, &signedTx)

		if verifyTxn(&signedTx, 0, groupCtx) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}
	}
}

func TestTxnValidationEmptySig(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signed, _, _ := generateTestObjects(100, 50, 0)

	for _, txn := range signed {
		groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{txn}, blockHeader, nil)
		require.NoError(t, err)
		if verifyTxn(&txn, 0, groupCtx) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}

		txn.Sig = crypto.Signature{}
		txn.Msig = crypto.MultisigSig{}
		txn.Lsig = transactions.LogicSig{}
		if verifyTxn(&txn, 0, groupCtx) == nil {
			t.Errorf("transaction %#v verified without sig", txn)
		}
	}
}

const spProto = protocol.ConsensusVersion("test-state-proof-enabled")

func TestTxnValidationStateProof(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	proto.StateProofInterval = 256
	config.Consensus[spProto] = proto

	stxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.StateProofTx,
			Header: transactions.Header{
				Sender:     transactions.StateProofSender,
				FirstValid: 0,
				LastValid:  10,
			},
		},
	}

	var blockHeader = bookkeeping.BlockHeader{
		RewardsState: bookkeeping.RewardsState{
			FeeSink:     feeSink,
			RewardsPool: poolAddr,
		},
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: spProto,
		},
	}

	groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{stxn}, blockHeader, nil)
	require.NoError(t, err)

	err = verifyTxn(&stxn, 0, groupCtx)
	require.NoError(t, err, "state proof txn %#v did not verify", stxn)

	stxn2 := stxn
	stxn2.Txn.Type = protocol.PaymentTx
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	err = verifyTxn(&stxn2, 0, groupCtx)
	require.Error(t, err, "payment txn %#v verified from StateProofSender", stxn2)

	secret := keypair()
	stxn2 = stxn
	stxn2.Txn.Header.Sender = basics.Address(secret.SignatureVerifier)
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	stxn2 = stxn2.Txn.Sign(secret)
	err = verifyTxn(&stxn2, 0, groupCtx)
	require.Error(t, err, "state proof txn %#v verified from non-StateProofSender", stxn2)

	// state proof txns are not allowed to have non-zero values for many fields
	stxn2 = stxn
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	err = verifyTxn(&stxn2, 0, groupCtx)
	require.Error(t, err, "state proof txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.Header.Note = []byte{'A'}
	err = verifyTxn(&stxn2, 0, groupCtx)
	require.Error(t, err, "state proof txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.Lease[0] = 1
	err = verifyTxn(&stxn2, 0, groupCtx)
	require.Error(t, err, "state proof txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.RekeyTo = basics.Address(secret.SignatureVerifier)
	err = verifyTxn(&stxn2, 0, groupCtx)
	require.Error(t, err, "state proof txn %#v verified", stxn2)
}

func TestDecodeNil(t *testing.T) {
	partitiontest.PartitionTest(t)

	// This is a regression test for improper decoding of a nil SignedTxn.
	// This is a subtle case because decoding a msgpack nil does not run
	// SignedTxn.CodecDecodeSelf().
	nilEncoding := []byte{0xc0}

	var st transactions.SignedTxn
	err := protocol.Decode(nilEncoding, &st)
	if err == nil {
		// This used to panic when run on a zero value of SignedTxn.
		groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{st}, blockHeader, nil)
		require.NoError(t, err)
		verifyTxn(&st, 0, groupCtx)
	}
}

func TestPaysetGroups(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, secrets, addrs := generateTestObjects(10000, 20, 50)
	blkHdr := createDummyBlockHeader()

	execPool := execpool.MakePool(t)
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)

	startPaysetGroupsTime := time.Now()
	err := PaysetGroups(context.Background(), txnGroups, blkHdr, verificationPool, MakeVerifiedTransactionCache(50000), nil)
	require.NoError(t, err)
	paysetGroupDuration := time.Now().Sub(startPaysetGroupsTime)

	// break the signature and see if it fails.
	txnGroups[0][0].Sig[0] = txnGroups[0][0].Sig[0] + 1
	err = PaysetGroups(context.Background(), txnGroups, blkHdr, verificationPool, MakeVerifiedTransactionCache(50000), nil)
	require.Error(t, err)

	// ensure the rest are fine
	err = PaysetGroups(context.Background(), txnGroups[1:], blkHdr, verificationPool, MakeVerifiedTransactionCache(50000), nil)
	require.NoError(t, err)

	// test the context cancelation:
	// we define a test that would take 10 seconds to execute, and try to abort at 1.5 seconds.
	txnCount := len(signedTxn) * 10 * int(time.Second/paysetGroupDuration)

	_, signedTxn, secrets, addrs = generateTestObjects(txnCount, 20, 50)

	txnGroups = generateTransactionGroups(signedTxn, secrets, addrs)

	ctx, ctxCancelFunc := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer ctxCancelFunc()
	waitCh := make(chan error, 1)
	go func() {
		defer close(waitCh)
		cache := MakeVerifiedTransactionCache(50000)
		waitCh <- PaysetGroups(ctx, txnGroups, blkHdr, verificationPool, cache, nil)
	}()
	startPaysetGroupsTime = time.Now()
	select {
	case err, ok := <-waitCh:
		if !ok {
			// channel is closed without a return
			require.Failf(t, "Channel got closed ?!", "")
		} else {
			actualDuration := time.Now().Sub(startPaysetGroupsTime)
			if err == nil {
				if actualDuration > 4*time.Second {
					// it took at least 2.5 seconds more than it should have had!
					require.Failf(t, "Failed after exceeding timeout with incorrect return code", "The function PaysetGroups was supposed to abort after 1.5 seconds with context.DeadlineExceeded, but aborted only after %v without any error", actualDuration)
				}
			} else {
				require.Equal(t, ctx.Err(), err)
				require.Equal(t, ctx.Err(), context.DeadlineExceeded)
				if actualDuration > 4*time.Second {
					// it took at least 2.5 seconds more than it should have had!
					require.Failf(t, "Failed after exceeding timeout", "The function PaysetGroups was supposed to abort after 1.5 seconds, but aborted only after %v", actualDuration)
				}
			}
		}
	case <-time.After(15 * time.Second):
		require.Failf(t, "Failed after exceeding timeout", "waited for 15 seconds while it should have aborted after 1.5 seconds")
	}
}

func BenchmarkPaysetGroups(b *testing.B) {
	if b.N < 2000 {
		b.N = 2000
	}
	_, signedTxn, secrets, addrs := generateTestObjects(b.N, 20, 50)
	blkHdr := createDummyBlockHeader()

	execPool := execpool.MakePool(b)
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, b)
	defer verificationPool.Shutdown()

	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)
	cache := MakeVerifiedTransactionCache(50000)

	b.ResetTimer()
	err := PaysetGroups(context.Background(), txnGroups, blkHdr, verificationPool, cache, nil)
	require.NoError(b, err)
	b.StopTimer()
}

func TestTxnGroupMixedSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, secrets, addrs := generateTestObjects(1, 20, 50)
	blkHdr := createDummyBlockHeader()

	// add a simple logic that verifies this condition:
	// sha256(arg0) == base64decode(5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=)
	op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
	require.NoError(t, err)

	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)

	dummyLedger := DummyLedgerForSignature{}
	_, err = TxnGroup(txnGroups[0], blkHdr, nil, &dummyLedger)
	require.NoError(t, err)

	///// no sig
	tmpSig := txnGroups[0][0].Sig
	txnGroups[0][0].Sig = crypto.Signature{}
	_, err = TxnGroup(txnGroups[0], blkHdr, nil, &dummyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "has no sig")
	txnGroups[0][0].Sig = tmpSig

	///// Sig + multiSig
	txnGroups[0][0].Msig.Subsigs = make([]crypto.MultisigSubsig, 1)
	txnGroups[0][0].Msig.Subsigs[0] = crypto.MultisigSubsig{
		Key: crypto.PublicKey{0x1},
		Sig: crypto.Signature{0x2},
	}
	_, err = TxnGroup(txnGroups[0], blkHdr, nil, &dummyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "should only have one of Sig or Msig or LogicSig")
	txnGroups[0][0].Msig.Subsigs = nil

	///// Sig + logic
	txnGroups[0][0].Lsig.Logic = op.Program
	_, err = TxnGroup(txnGroups[0], blkHdr, nil, &dummyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "should only have one of Sig or Msig or LogicSig")
	txnGroups[0][0].Lsig.Logic = []byte{}

	///// MultiSig + logic
	txnGroups[0][0].Sig = crypto.Signature{}
	txnGroups[0][0].Lsig.Logic = op.Program
	txnGroups[0][0].Msig.Subsigs = make([]crypto.MultisigSubsig, 1)
	txnGroups[0][0].Msig.Subsigs[0] = crypto.MultisigSubsig{
		Key: crypto.PublicKey{0x1},
		Sig: crypto.Signature{0x2},
	}
	_, err = TxnGroup(txnGroups[0], blkHdr, nil, &dummyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "should only have one of Sig or Msig or LogicSig")
	txnGroups[0][0].Lsig.Logic = []byte{}
	txnGroups[0][0].Sig = tmpSig
	txnGroups[0][0].Msig.Subsigs = nil

	/////  logic with sig and multi sig
	txnGroups[0][0].Sig = crypto.Signature{}
	txnGroups[0][0].Lsig.Logic = op.Program
	txnGroups[0][0].Lsig.Sig = tmpSig
	txnGroups[0][0].Lsig.Msig.Subsigs = make([]crypto.MultisigSubsig, 1)
	txnGroups[0][0].Lsig.Msig.Subsigs[0] = crypto.MultisigSubsig{
		Key: crypto.PublicKey{0x1},
		Sig: crypto.Signature{0x2},
	}
	_, err = TxnGroup(txnGroups[0], blkHdr, nil, &dummyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "should only have one of Sig or Msig")

}

func generateTransactionGroups(signedTxns []transactions.SignedTxn, secrets []*crypto.SignatureSecrets, addrs []basics.Address) [][]transactions.SignedTxn {
	addrToSecret := make(map[basics.Address]*crypto.SignatureSecrets)
	for i, addr := range addrs {
		addrToSecret[addr] = secrets[i]
	}

	txnGroups := make([][]transactions.SignedTxn, 0, len(signedTxns))
	for i := 0; i < len(signedTxns); i++ {
		txnPerGroup := 1 + rand.Intn(15)
		if i+txnPerGroup >= len(signedTxns) {
			txnPerGroup = len(signedTxns) - i - 1
		}
		newGroup := signedTxns[i : i+txnPerGroup+1]
		var txGroup transactions.TxGroup
		for _, txn := range newGroup {
			txGroup.TxGroupHashes = append(txGroup.TxGroupHashes, crypto.HashObj(txn.Txn))
		}
		groupHash := crypto.HashObj(txGroup)
		for j := range newGroup {
			newGroup[j].Txn.Group = groupHash
			newGroup[j].Sig = addrToSecret[newGroup[j].Txn.Sender].Sign(&newGroup[j].Txn)
		}
		txnGroups = append(txnGroups, newGroup)
		i += txnPerGroup
	}

	return txnGroups
}

func TestTxnGroupCacheUpdate(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, secrets, addrs := generateTestObjects(100, 20, 50)
	blkHdr := createDummyBlockHeader()

	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)
	breakSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Sig[0]++
	}
	restoreSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Sig[0]--
	}
	verifyGroup(t, txnGroups, blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchVerificationFailed.Error())
}

// TestTxnGroupCacheUpdateMultiSig makes sure that a payment transaction signed with multisig
// is valid (and added to the cache) only if all signatures in the multisig are correct
func TestTxnGroupCacheUpdateMultiSig(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, _, _ := generateMultiSigTxn(100, 30, 50, t)
	blkHdr := createDummyBlockHeader()

	txnGroups := make([][]transactions.SignedTxn, len(signedTxn))
	for i := 0; i < len(txnGroups); i++ {
		txnGroups[i] = make([]transactions.SignedTxn, 1)
		txnGroups[i][0] = signedTxn[i]
	}
	breakSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Msig.Subsigs[0].Sig[0]++
	}
	restoreSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Msig.Subsigs[0].Sig[0]--
	}
	verifyGroup(t, txnGroups, blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchVerificationFailed.Error())
}

// TestTxnGroupCacheUpdateFailLogic test makes sure that a payment transaction contains a logic (and no signature)
// is valid (and added to the cache) only if logic passes
func TestTxnGroupCacheUpdateFailLogic(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, _, _ := generateTestObjects(100, 20, 50)
	blkHdr := createDummyBlockHeader()

	// sign the transcation with logic
	for i := 0; i < len(signedTxn); i++ {
		// add a simple logic that verifies this condition:
		// sha256(arg0) == base64decode(5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=)
		op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
		require.NoError(t, err)
		signedTxn[i].Lsig.Logic = op.Program
		program := logic.Program(op.Program)
		signedTxn[i].Txn.Sender = basics.Address(crypto.HashObj(&program))
		signedTxn[i].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
		signedTxn[i].Sig = crypto.Signature{}
	}

	txnGroups := make([][]transactions.SignedTxn, len(signedTxn))
	for i := 0; i < len(txnGroups); i++ {
		txnGroups[i] = make([]transactions.SignedTxn, 1)
		txnGroups[i][0] = signedTxn[i]
	}

	breakSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]++
	}
	restoreSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]--
	}
	verifyGroup(t, txnGroups, blkHdr, breakSignatureFunc, restoreSignatureFunc, "rejected by logic")

}

// TestTxnGroupCacheUpdateLogicWithSig makes sure that a payment transaction contains logicsig signed with single signature is valid (and added to the cache) only
// if the logic passes and the signature is correct.
// for this, we will break the signature and make sure that txn verification fails.
func TestTxnGroupCacheUpdateLogicWithSig(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, secrets, addresses := generateTestObjects(100, 20, 50)
	blkHdr := createDummyBlockHeader()

	for i := 0; i < len(signedTxn); i++ {
		// add a simple logic that verifies this condition:
		// sha256(arg0) == base64decode(5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=)
		op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
		require.NoError(t, err)

		s := rand.Intn(len(secrets))
		signedTxn[i].Sig = crypto.Signature{}
		signedTxn[i].Txn.Sender = addresses[s]
		signedTxn[i].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
		signedTxn[i].Lsig.Logic = op.Program
		program := logic.Program(op.Program)
		signedTxn[i].Lsig.Sig = secrets[s].Sign(program)

	}

	txnGroups := make([][]transactions.SignedTxn, len(signedTxn))
	for i := 0; i < len(txnGroups); i++ {
		txnGroups[i] = make([]transactions.SignedTxn, 1)
		txnGroups[i][0] = signedTxn[i]
	}

	breakSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Lsig.Sig[0]++
	}
	restoreSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Lsig.Sig[0]--
	}
	verifyGroup(t, txnGroups, blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchVerificationFailed.Error())

	// signature is correct and logic fails
	breakSignatureFunc = func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]++
	}
	restoreSignatureFunc = func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]--
	}
	verifyGroup(t, txnGroups, blkHdr, breakSignatureFunc, restoreSignatureFunc, "rejected by logic")
}

// TestTxnGroupCacheUpdateLogicWithMultiSig makes sure that a payment transaction contains logicsig signed with multisig is valid
// if the logic passes and the multisig is correct.
// for this, we will break one of the multisig and the logic and make sure that txn verification fails.
func TestTxnGroupCacheUpdateLogicWithMultiSig(t *testing.T) {
	partitiontest.PartitionTest(t)

	secrets, _, pks, multiAddress := generateMultiSigAccounts(t, 30)
	blkHdr := createDummyBlockHeader()

	const numOfTxn = 20
	signedTxn := make([]transactions.SignedTxn, numOfTxn)

	numMultiSigAcct := len(multiAddress)
	for i := 0; i < numOfTxn; i++ {
		s := rand.Intn(numMultiSigAcct)
		r := rand.Intn(numMultiSigAcct)
		a := rand.Intn(1000)
		f := config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee + uint64(rand.Intn(10))

		signedTxn[i].Txn = transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      multiAddress[s],
				Fee:         basics.MicroAlgos{Raw: f},
				FirstValid:  basics.Round(1),
				LastValid:   basics.Round(100),
				GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: multiAddress[r],
				Amount:   basics.MicroAlgos{Raw: uint64(a)},
			},
		}
		// add a simple logic that verifies this condition:
		// sha256(arg0) == base64decode(5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=)
		op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
		require.NoError(t, err)

		signedTxn[i].Sig = crypto.Signature{}
		signedTxn[i].Txn.Sender = multiAddress[s]
		signedTxn[i].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
		signedTxn[i].Lsig.Logic = op.Program
		program := logic.Program(op.Program)

		// create multi sig that 2 out of 3 has signed the txn
		var sigs [2]crypto.MultisigSig
		for j := 0; j < 2; j++ {
			msig, err := crypto.MultisigSign(program, crypto.Digest(multiAddress[s]), 1, 2, pks[3*s:3*s+3], *secrets[3*s+j])
			require.NoError(t, err)
			sigs[j] = msig
		}
		msig, err := crypto.MultisigAssemble(sigs[:])
		require.NoError(t, err)
		signedTxn[i].Lsig.Msig = msig
	}

	txnGroups := make([][]transactions.SignedTxn, len(signedTxn))
	for i := 0; i < len(txnGroups); i++ {
		txnGroups[i] = make([]transactions.SignedTxn, 1)
		txnGroups[i][0] = signedTxn[i]
	}

	breakSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Lsig.Msig.Subsigs[0].Sig[0]++
	}
	restoreSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Lsig.Msig.Subsigs[0].Sig[0]--
	}

	verifyGroup(t, txnGroups, blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchVerificationFailed.Error())
	// signature is correct and logic fails
	breakSignatureFunc = func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]++
	}
	restoreSignatureFunc = func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]--
	}
	verifyGroup(t, txnGroups, blkHdr, breakSignatureFunc, restoreSignatureFunc, "rejected by logic")
}

func createDummyBlockHeader() bookkeeping.BlockHeader {
	return bookkeeping.BlockHeader{
		Round:       50,
		GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
		RewardsState: bookkeeping.RewardsState{
			FeeSink:     feeSink,
			RewardsPool: poolAddr,
		},
	}
}

// verifyGroup uses TxnGroup to verify txns and add them to the
// cache. Then makes sure that only the valid txns are verified and added to
// the cache.
func verifyGroup(t *testing.T, txnGroups [][]transactions.SignedTxn, blkHdr bookkeeping.BlockHeader, breakSig func(txn *transactions.SignedTxn), restoreSig func(txn *transactions.SignedTxn), errorString string) {
	cache := MakeVerifiedTransactionCache(1000)

	breakSig(&txnGroups[0][0])

	dummeyLedger := DummyLedgerForSignature{}
	_, err := TxnGroup(txnGroups[0], blkHdr, cache, &dummeyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), errorString)

	// The txns should not be in the cache
	unverifiedGroups := cache.GetUnverifiedTransactionGroups(txnGroups[:1], spec, protocol.ConsensusCurrentVersion)
	require.Len(t, unverifiedGroups, 1)

	unverifiedGroups = cache.GetUnverifiedTransactionGroups(txnGroups[:2], spec, protocol.ConsensusCurrentVersion)
	require.Len(t, unverifiedGroups, 2)

	_, err = TxnGroup(txnGroups[1], blkHdr, cache, &dummeyLedger)
	require.NoError(t, err)

	// Only the second txn should be in the cache
	unverifiedGroups = cache.GetUnverifiedTransactionGroups(txnGroups[:2], spec, protocol.ConsensusCurrentVersion)
	require.Len(t, unverifiedGroups, 1)

	restoreSig(&txnGroups[0][0])

	_, err = TxnGroup(txnGroups[0], blkHdr, cache, &dummeyLedger)
	require.NoError(t, err)

	// Both transactions should be in the cache
	unverifiedGroups = cache.GetUnverifiedTransactionGroups(txnGroups[:2], spec, protocol.ConsensusCurrentVersion)
	require.Len(t, unverifiedGroups, 0)

	cache = MakeVerifiedTransactionCache(1000)
	// Break a random signature
	txgIdx := rand.Intn(len(txnGroups))
	txIdx := rand.Intn(len(txnGroups[txgIdx]))
	breakSig(&txnGroups[txgIdx][txIdx])

	numFailed := 0

	// Add them to the cache by verifying them
	for _, txng := range txnGroups {
		_, err = TxnGroup(txng, blkHdr, cache, &dummeyLedger)
		if err != nil {
			require.Error(t, err)
			require.Contains(t, err.Error(), errorString)
			numFailed++
		}
	}
	require.Equal(t, 1, numFailed)

	// Only one transaction should not be in cache
	unverifiedGroups = cache.GetUnverifiedTransactionGroups(txnGroups, spec, protocol.ConsensusCurrentVersion)
	require.Len(t, unverifiedGroups, 1)

	require.Equal(t, unverifiedGroups[0], txnGroups[txgIdx])
	restoreSig(&txnGroups[txgIdx][txIdx])
}

func BenchmarkTxn(b *testing.B) {
	if b.N < 2000 {
		b.N = 2000
	}
	_, signedTxn, secrets, addrs := generateTestObjects(b.N, 20, 50)
	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round:       50,
			GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
			RewardsState: bookkeeping.RewardsState{
				FeeSink:     feeSink,
				RewardsPool: poolAddr,
			},
		},
	}
	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)

	b.ResetTimer()
	for _, txnGroup := range txnGroups {
		groupCtx, err := PrepareGroupContext(txnGroup, blk.BlockHeader, nil)
		require.NoError(b, err)
		for i, txn := range txnGroup {
			err := verifyTxn(&txn, i, groupCtx)
			require.NoError(b, err)
		}
	}
	b.StopTimer()
}
