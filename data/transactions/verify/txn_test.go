// Copyright (C) 2019-2023 Algorand, Inc.
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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
)

var feeSink = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var blockHeader = &bookkeeping.BlockHeader{
	RewardsState: bookkeeping.RewardsState{
		FeeSink:     feeSink,
		RewardsPool: poolAddr,
	},
	UpgradeState: bookkeeping.UpgradeState{
		CurrentProtocol: protocol.ConsensusCurrentVersion,
	},
}
var protoMaxGroupSize = config.Consensus[protocol.ConsensusCurrentVersion].MaxTxGroupSize
var txBacklogSize = config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnBytesPerBlock / 200

var spec = transactions.SpecialAddresses{
	FeeSink:     feeSink,
	RewardsPool: poolAddr,
}

func verifyTxn(s *transactions.SignedTxn, txnIdx int, groupCtx *GroupContext) error {
	batchVerifier := crypto.MakeBatchVerifier()

	if err := txnBatchPrep(s, txnIdx, groupCtx, batchVerifier, nil); err != nil {
		return err
	}
	return batchVerifier.Verify()
}

type DummyLedgerForSignature struct {
	badHdr bool
}

func (d *DummyLedgerForSignature) BlockHdrCached(basics.Round) (bookkeeping.BlockHeader, error) {
	return createDummyBlockHeader(), nil
}
func (d *DummyLedgerForSignature) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {
	if d.badHdr {
		return bookkeeping.BlockHeader{}, fmt.Errorf("test error block hdr")
	}
	return createDummyBlockHeader(), nil
}
func (d *DummyLedgerForSignature) Latest() basics.Round {
	return 0
}
func (d *DummyLedgerForSignature) RegisterBlockListeners([]ledgercore.BlockListener) {
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

		txs[i] = createPayTransaction(f, iss, exp, a, multiAddress[s], multiAddress[r])
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

func generateTestObjects(numTxs, numAccs, noteOffset int, blockRound basics.Round) ([]transactions.Transaction, []transactions.SignedTxn, []*crypto.SignatureSecrets, []basics.Address) {
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

		txs[i] = createPayTransaction(f, iss, exp, a, addresses[s], addresses[r])
		noteField := make([]byte, binary.MaxVarintLen64)
		binary.PutUvarint(noteField, uint64(i+noteOffset))
		txs[i].Note = noteField

		signed[i] = txs[i].Sign(secrets[s])
		u += 100
	}

	return txs, signed, secrets, addresses
}

func TestSignedPayment(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	payments, stxns, secrets, addrs := generateTestObjects(1, 1, 0, 0)
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

	_, signed, _, _ := generateTestObjects(100, 50, 0, 0)

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

	_, signed, _, _ := generateTestObjects(100, 50, 0, 0)

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

func TestTxnValidationStateProof(t *testing.T) { //nolint:paralleltest // Not parallel because it modifies config.Consensus
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

	var blockHeader = &bookkeeping.BlockHeader{
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

func TestTxnGroupWithTracer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	account := keypair()
	accountAddr := basics.Address(account.SignatureVerifier)

	ops1, err := logic.AssembleString(`#pragma version 6
pushint 1`)
	require.NoError(t, err)
	program1 := ops1.Program
	program1Addr := basics.Address(logic.HashProgram(program1))

	ops2, err := logic.AssembleString(`#pragma version 6
pushbytes "test"
pop
pushint 1`)
	require.NoError(t, err)
	program2 := ops2.Program
	program2Addr := basics.Address(logic.HashProgram(program2))

	// this shouldn't be invoked during this test
	appProgram := "err"

	lsigPay := txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   program1Addr,
		Receiver: accountAddr,
		Fee:      proto.MinTxnFee,
	}

	normalSigAppCall := txntest.Txn{
		Type:              protocol.ApplicationCallTx,
		Sender:            accountAddr,
		ApprovalProgram:   appProgram,
		ClearStateProgram: appProgram,
		Fee:               proto.MinTxnFee,
	}

	lsigAppCall := txntest.Txn{
		Type:              protocol.ApplicationCallTx,
		Sender:            program2Addr,
		ApprovalProgram:   appProgram,
		ClearStateProgram: appProgram,
		Fee:               proto.MinTxnFee,
	}

	txntest.Group(&lsigPay, &normalSigAppCall, &lsigAppCall)

	txgroup := []transactions.SignedTxn{
		{
			Lsig: transactions.LogicSig{
				Logic: program1,
			},
			Txn: lsigPay.Txn(),
		},
		normalSigAppCall.Txn().Sign(account),
		{
			Lsig: transactions.LogicSig{
				Logic: program2,
			},
			Txn: lsigAppCall.Txn(),
		},
	}

	mockTracer := &mocktracer.Tracer{}
	_, err = TxnGroupWithTracer(txgroup, blockHeader, nil, logic.NoHeaderLedger{}, mockTracer)
	require.NoError(t, err)

	expectedEvents := []mocktracer.Event{
		mocktracer.BeforeProgram(logic.ModeSig),             // first txn start
		mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(), // first txn LogicSig: 1 op
		mocktracer.AfterProgram(logic.ModeSig), // first txn end
		// nothing for second txn (not signed with a LogicSig)
		mocktracer.BeforeProgram(logic.ModeSig),                                                                                                                       // third txn start
		mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(), mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(), mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(), // third txn LogicSig: 3 ops
		mocktracer.AfterProgram(logic.ModeSig), // third txn end
	}
	require.Equal(t, expectedEvents, mockTracer.Events)
}

func TestPaysetGroups(t *testing.T) {
	partitiontest.PartitionTest(t)

	if testing.Short() {
		t.Log("this is a long test and skipping for -short")
		return
	}

	_, signedTxn, secrets, addrs := generateTestObjects(10000, 20, 0, 50)
	blkHdr := createDummyBlockHeader()

	execPool := execpool.MakePool(t)
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

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

	_, signedTxn, secrets, addrs = generateTestObjects(txnCount, 20, 0, 50)

	txnGroups = generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

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
	_, signedTxn, secrets, addrs := generateTestObjects(b.N, 20, 0, 50)
	blkHdr := createDummyBlockHeader()

	execPool := execpool.MakePool(b)
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, b)
	defer verificationPool.Shutdown()

	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)
	cache := MakeVerifiedTransactionCache(50000)

	b.ResetTimer()
	err := PaysetGroups(context.Background(), txnGroups, blkHdr, verificationPool, cache, nil)
	require.NoError(b, err)
	b.StopTimer()
}

func TestTxnGroupMixedSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, secrets, addrs := generateTestObjects(1, 20, 0, 50)
	blkHdr := createDummyBlockHeader()

	// add a simple logic that verifies this condition:
	// sha256(arg0) == base64decode(5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=)
	op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
	require.NoError(t, err)

	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

	dummyLedger := DummyLedgerForSignature{}
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
	require.NoError(t, err)

	///// no sig
	tmpSig := txnGroups[0][0].Sig
	txnGroups[0][0].Sig = crypto.Signature{}
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "has no sig")
	txnGroups[0][0].Sig = tmpSig

	///// Sig + multiSig
	txnGroups[0][0].Msig.Subsigs = make([]crypto.MultisigSubsig, 1)
	txnGroups[0][0].Msig.Subsigs[0] = crypto.MultisigSubsig{
		Key: crypto.PublicKey{0x1},
		Sig: crypto.Signature{0x2},
	}
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "should only have one of Sig or Msig or LogicSig")
	txnGroups[0][0].Msig.Subsigs = nil

	///// Sig + logic
	txnGroups[0][0].Lsig.Logic = op.Program
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
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
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
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
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "should only have one of Sig or Msig")

}

func generateTransactionGroups(maxGroupSize int, signedTxns []transactions.SignedTxn,
	secrets []*crypto.SignatureSecrets, addrs []basics.Address) [][]transactions.SignedTxn {
	addrToSecret := make(map[basics.Address]*crypto.SignatureSecrets)
	for i, addr := range addrs {
		addrToSecret[addr] = secrets[i]
	}

	txnGroups := make([][]transactions.SignedTxn, 0, len(signedTxns))
	for i := 0; i < len(signedTxns); {
		txnsInGroup := rand.Intn(protoMaxGroupSize-1) + 1
		if txnsInGroup > maxGroupSize {
			txnsInGroup = maxGroupSize
		}
		if i+txnsInGroup > len(signedTxns) {
			txnsInGroup = len(signedTxns) - i
		}

		newGroup := signedTxns[i : i+txnsInGroup]
		var txGroup transactions.TxGroup
		if txnsInGroup > 1 {
			for _, txn := range newGroup {
				txGroup.TxGroupHashes = append(txGroup.TxGroupHashes, crypto.HashObj(txn.Txn))
			}
		}
		groupHash := crypto.HashObj(txGroup)
		for j := range newGroup {
			if txnsInGroup > 1 {
				newGroup[j].Txn.Group = groupHash
			}
			newGroup[j].Sig = addrToSecret[newGroup[j].Txn.Sender].Sign(&newGroup[j].Txn)
		}
		txnGroups = append(txnGroups, newGroup)
		i += txnsInGroup
	}

	return txnGroups
}

func TestTxnGroupCacheUpdate(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, secrets, addrs := generateTestObjects(100, 20, 0, 50)
	blkHdr := createDummyBlockHeader()

	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)
	breakSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Sig[0]++
	}
	restoreSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Sig[0]--
	}
	verifyGroup(t, txnGroups, &blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchHasFailedSigs.Error())
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
	verifyGroup(t, txnGroups, &blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchHasFailedSigs.Error())
}

// TestTxnGroupCacheUpdateFailLogic test makes sure that a payment transaction contains a logic (and no signature)
// is valid (and added to the cache) only if logic passes
func TestTxnGroupCacheUpdateFailLogic(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, _, _ := generateTestObjects(100, 20, 0, 50)
	blkHdr := createDummyBlockHeader()

	// sign the transaction with logic
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
	initCounter := logicCostTotal.GetUint64Value()
	verifyGroup(t, txnGroups, &blkHdr, breakSignatureFunc, restoreSignatureFunc, "rejected by logic")
	currentCounter := logicCostTotal.GetUint64Value()
	require.Greater(t, currentCounter, initCounter)
}

// TestTxnGroupCacheUpdateLogicWithSig makes sure that a payment transaction contains logicsig signed with single signature is valid (and added to the cache) only
// if the logic passes and the signature is correct.
// for this, we will break the signature and make sure that txn verification fails.
func TestTxnGroupCacheUpdateLogicWithSig(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxn, secrets, addresses := generateTestObjects(100, 20, 0, 50)
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
	verifyGroup(t, txnGroups, &blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchHasFailedSigs.Error())

	// signature is correct and logic fails
	breakSignatureFunc = func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]++
	}
	restoreSignatureFunc = func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]--
	}
	verifyGroup(t, txnGroups, &blkHdr, breakSignatureFunc, restoreSignatureFunc, "rejected by logic")
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

		signedTxn[i].Txn = createPayTransaction(f, 1, 100, a, multiAddress[s], multiAddress[r])
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

	verifyGroup(t, txnGroups, &blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchHasFailedSigs.Error())
	// signature is correct and logic fails
	breakSignatureFunc = func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]++
	}
	restoreSignatureFunc = func(txn *transactions.SignedTxn) {
		txn.Lsig.Args[0][0]--
	}
	verifyGroup(t, txnGroups, &blkHdr, breakSignatureFunc, restoreSignatureFunc, "rejected by logic")
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

func createPayTransaction(fee uint64, fv, lv, amount int, sender, receiver basics.Address) transactions.Transaction {
	return transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: fee},
			FirstValid:  basics.Round(fv),
			LastValid:   basics.Round(lv),
			GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: uint64(amount)},
		},
	}
}

// verifyGroup uses TxnGroup to verify txns and add them to the
// cache. Then makes sure that only the valid txns are verified and added to
// the cache.
func verifyGroup(t *testing.T, txnGroups [][]transactions.SignedTxn, blkHdr *bookkeeping.BlockHeader, breakSig func(txn *transactions.SignedTxn), restoreSig func(txn *transactions.SignedTxn), errorString string) {
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
	_, signedTxn, secrets, addrs := generateTestObjects(b.N, 20, 0, 50)
	blk := bookkeeping.Block{BlockHeader: createDummyBlockHeader()}
	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

	b.ResetTimer()
	for _, txnGroup := range txnGroups {
		groupCtx, err := PrepareGroupContext(txnGroup, &blk.BlockHeader, nil)
		require.NoError(b, err)
		for i, txn := range txnGroup {
			err := verifyTxn(&txn, i, groupCtx)
			require.NoError(b, err)
		}
	}
	b.StopTimer()
}

var droppedFromPool = metrics.MakeCounter(metrics.MetricName{Name: "test_streamVerifierTestCore_messages_dropped_pool", Description: "Test streamVerifierTestCore messages dropped from pool"})

func streamVerifierTestCore(txnGroups [][]transactions.SignedTxn, badTxnGroups map[uint64]struct{},
	expectedError error, t *testing.T) (sv *StreamVerifier) {

	numOfTxnGroups := len(txnGroups)
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	cache := MakeVerifiedTransactionCache(50000)

	defer cancel()

	stxnChan := make(chan *UnverifiedElement)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedElement)
	sv, err := MakeStreamVerifier(stxnChan, resultChan, droppedChan, &DummyLedgerForSignature{}, verificationPool, cache)
	require.NoError(t, err)
	sv.Start(ctx)

	wg := sync.WaitGroup{}

	errChan := make(chan error)
	var badSigResultCounter int
	var goodSigResultCounter int

	wg.Add(1)
	go processResults(ctx, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	wg.Add(1)
	// send txn groups to be verified
	go func() {
		defer wg.Done()
		for _, tg := range txnGroups {
			stxnChan <- &UnverifiedElement{TxnGroup: tg, BacklogMessage: nil}
		}
	}()

	for err := range errChan {
		require.ErrorContains(t, err, expectedError.Error())
	}

	wg.Wait()

	verifyResults(txnGroups, badTxnGroups, cache, badSigResultCounter, goodSigResultCounter, t)
	return sv
}

func processResults(ctx context.Context, errChan chan<- error, resultChan <-chan *VerificationResult,
	numOfTxnGroups int, badTxnGroups map[uint64]struct{},
	badSigResultCounter, goodSigResultCounter *int, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(errChan)
	// process the results
	for x := 0; x < numOfTxnGroups; x++ {
		select {
		case <-ctx.Done():
		case result := <-resultChan:
			u, _ := binary.Uvarint(result.TxnGroup[0].Txn.Note)
			if _, has := badTxnGroups[u]; has {
				(*badSigResultCounter)++
				if result.Err == nil {
					err := fmt.Errorf("%dth (%d)transaction varified with a bad sig", x, u)
					errChan <- err
					return
				}
				// we expected an error, but it is not the general crypto error
				if result.Err != crypto.ErrBatchHasFailedSigs {
					errChan <- result.Err
				}
			} else {
				(*goodSigResultCounter)++
				if result.Err != nil {
					errChan <- result.Err
				}
			}
		}
	}
}

func verifyResults(txnGroups [][]transactions.SignedTxn, badTxnGroups map[uint64]struct{},
	cache VerifiedTransactionCache,
	badSigResultCounter, goodSigResultCounter int, t *testing.T) {
	// check if all txns have been checked.
	require.Equal(t, len(txnGroups), badSigResultCounter+goodSigResultCounter)
	require.Equal(t, len(badTxnGroups), badSigResultCounter)

	// check the cached transactions
	// note that the result of each verified txn group is send before the batch is added to the cache
	// the test does not know if the batch is not added to the cache yet, so some elts might be missing from the cache
	unverifiedGroups := cache.GetUnverifiedTransactionGroups(txnGroups, spec, protocol.ConsensusCurrentVersion)
	require.GreaterOrEqual(t, len(unverifiedGroups), badSigResultCounter)
	for _, txn := range unverifiedGroups {
		u, _ := binary.Uvarint(txn[0].Txn.Note)
		if _, has := badTxnGroups[u]; has {
			delete(badTxnGroups, u)
		}
	}
	require.Empty(t, badTxnGroups, "unverifiedGroups should have all the transactions with invalid sigs")
}

func getSignedTransactions(numOfTxns, maxGrpSize, noteOffset int, badTxnProb float32) (txnGroups [][]transactions.SignedTxn, badTxnGroups map[uint64]struct{}) {

	_, signedTxn, secrets, addrs := generateTestObjects(numOfTxns, 20, noteOffset, 50)
	txnGroups = generateTransactionGroups(maxGrpSize, signedTxn, secrets, addrs)

	badTxnGroups = make(map[uint64]struct{})

	for tgi := range txnGroups {
		if rand.Float32() < badTxnProb {
			// make a bad sig
			t := rand.Intn(len(txnGroups[tgi]))
			txnGroups[tgi][t].Sig[0] = txnGroups[tgi][t].Sig[0] + 1
			u, _ := binary.Uvarint(txnGroups[tgi][0].Txn.Note)
			badTxnGroups[u] = struct{}{}
		}
	}
	return

}

// TestStreamVerifier tests the basic functionality
func TestStreamVerifier(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 4000
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, protoMaxGroupSize, 0, 0.5)

	sv := streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
}

// TestStreamVerifierCases tests various valid and invalid transaction signature cases
func TestStreamVerifierCases(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 10
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, 1, 0, 0)
	mod := 1

	// txn with 0 sigs
	txnGroups[mod][0].Sig = crypto.Signature{}
	u, _ := binary.Uvarint(txnGroups[mod][0].Txn.Note)
	badTxnGroups[u] = struct{}{}
	sv := streamVerifierTestCore(txnGroups, badTxnGroups, errTxnSigHasNoSig, t)
	sv.WaitForStop()
	mod++

	_, signedTxns, secrets, addrs := generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxns, secrets, addrs)
	badTxnGroups = make(map[uint64]struct{})

	// invalid stateproof txn
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Type = protocol.StateProofTx
	txnGroups[mod][0].Txn.Header.Sender = transactions.StateProofSender
	u, _ = binary.Uvarint(txnGroups[mod][0].Txn.Note)
	badTxnGroups[u] = struct{}{}
	errFeeMustBeZeroInStateproofTxn := errors.New("fee must be zero in state-proof transaction")
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, errFeeMustBeZeroInStateproofTxn, t)
	sv.WaitForStop()
	mod++

	_, signedTxns, secrets, addrs = generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxns, secrets, addrs)
	badTxnGroups = make(map[uint64]struct{})

	// acceptable stateproof txn
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Note = nil
	txnGroups[mod][0].Txn.Type = protocol.StateProofTx
	txnGroups[mod][0].Txn.Header.Fee = basics.MicroAlgos{Raw: 0}
	txnGroups[mod][0].Txn.Header.Sender = transactions.StateProofSender
	txnGroups[mod][0].Txn.PaymentTxnFields = transactions.PaymentTxnFields{}
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
	mod++

	// multisig
	_, mSigTxn, _, _ := generateMultiSigTxn(1, 6, 50, t)
	txnGroups[mod] = mSigTxn
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
	mod++

	_, signedTxn, secrets, addrs := generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxn, secrets, addrs)
	badTxnGroups = make(map[uint64]struct{})

	// logicsig
	// add a simple logic that verifies this condition:
	// sha256(arg0) == base64decode(5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=)
	op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
	require.NoError(t, err)
	s := rand.Intn(len(secrets))
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Sender = addrs[s]
	txnGroups[mod][0].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	txnGroups[mod][0].Lsig.Logic = op.Program
	program := logic.Program(op.Program)
	txnGroups[mod][0].Lsig.Sig = secrets[s].Sign(program)
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
	mod++

	// bad lgicsig
	s = rand.Intn(len(secrets))
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Sender = addrs[s]
	txnGroups[mod][0].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	txnGroups[mod][0].Lsig.Args[0][0]++
	txnGroups[mod][0].Lsig.Logic = op.Program
	txnGroups[mod][0].Lsig.Sig = secrets[s].Sign(program)
	u, _ = binary.Uvarint(txnGroups[mod][0].Txn.Note)
	badTxnGroups[u] = struct{}{}
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, errors.New("rejected by logic"), t)
	sv.WaitForStop()
	mod++

	_, signedTxn, secrets, addrs = generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxn, secrets, addrs)
	badTxnGroups = make(map[uint64]struct{})

	// txn with sig and msig
	txnGroups[mod][0].Msig = mSigTxn[0].Msig
	u, _ = binary.Uvarint(txnGroups[mod][0].Txn.Note)
	badTxnGroups[u] = struct{}{}
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, errTxnSigNotWellFormed, t)
	sv.WaitForStop()
}

// TestStreamVerifierIdel starts the verifer and sends nothing, to trigger the timer, then sends a txn
func TestStreamVerifierIdel(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 1
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, protoMaxGroupSize, 0, 0.5)

	sv := streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
}

func TestGetNumberOfBatchableSigsInGroup(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 10
	txnGroups, _ := getSignedTransactions(numOfTxns, 1, 0, 0)
	mod := 1

	// txn with 0 sigs
	txnGroups[mod][0].Sig = crypto.Signature{}
	batchSigs, err := getNumberOfBatchableSigsInGroup(txnGroups[mod])
	require.ErrorIs(t, err, errTxnSigHasNoSig)
	mod++

	_, signedTxns, secrets, addrs := generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxns, secrets, addrs)
	batchSigs, err = getNumberOfBatchableSigsInGroup(txnGroups[0])
	require.NoError(t, err)
	require.Equal(t, uint64(1), batchSigs)

	// stateproof txn
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Type = protocol.StateProofTx
	txnGroups[mod][0].Txn.Header.Sender = transactions.StateProofSender
	batchSigs, err = getNumberOfBatchableSigsInGroup(txnGroups[mod])
	require.NoError(t, err)
	require.Equal(t, uint64(0), batchSigs)
	mod++

	// multisig
	_, mSigTxn, _, _ := generateMultiSigTxn(1, 6, 50, t)
	batchSigs, err = getNumberOfBatchableSigsInGroup(mSigTxn)
	require.NoError(t, err)
	require.Equal(t, uint64(2), batchSigs)
	mod++

	_, signedTxn, secrets, addrs := generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxn, secrets, addrs)

	// logicsig
	op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
	require.NoError(t, err)
	s := rand.Intn(len(secrets))
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Sender = addrs[s]
	txnGroups[mod][0].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	txnGroups[mod][0].Lsig.Logic = op.Program
	program := logic.Program(op.Program)
	txnGroups[mod][0].Lsig.Sig = secrets[s].Sign(program)
	batchSigs, err = getNumberOfBatchableSigsInGroup(txnGroups[mod])
	require.NoError(t, err)
	require.Equal(t, uint64(0), batchSigs)
	mod++

	// txn with sig and msig
	_, signedTxn, secrets, addrs = generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxn, secrets, addrs)
	txnGroups[mod][0].Msig = mSigTxn[0].Msig
	batchSigs, err = getNumberOfBatchableSigsInGroup(txnGroups[mod])
	require.ErrorIs(t, err, errTxnSigNotWellFormed)
}

// TestStreamVerifierPoolShutdown tests what happens when the exec pool shuts down
func TestStreamVerifierPoolShutdown(t *testing.T) { //nolint:paralleltest // Not parallel because it depends on the default logger
	partitiontest.PartitionTest(t)

	// only one transaction should be sufficient for the batch verifier
	// to realize the pool is terminated and to shut down
	numOfTxns := 1
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, protoMaxGroupSize, 0, 0.5)

	// check the logged information
	var logBuffer bytes.Buffer
	log := logging.Base()
	log.SetOutput(&logBuffer)
	log.SetLevel(logging.Info)

	// prepare the stream verifier
	numOfTxnGroups := len(txnGroups)
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	_, buffLen := verificationPool.BufferSize()

	// make sure the pool is shut down and the buffer is full
	holdTasks := make(chan interface{})
	for x := 0; x < buffLen+runtime.NumCPU(); x++ {
		verificationPool.EnqueueBacklog(context.Background(),
			func(arg interface{}) interface{} { <-holdTasks; return nil }, nil, nil)
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Shutdown will block until all tasks held by holdTasks is released
		verificationPool.Shutdown()
	}()
	// Send more tasks to break the backlog worker  after b.pool.Enqueue returns the error
	for x := 0; x < 100; x++ {
		verificationPool.EnqueueBacklog(context.Background(),
			func(arg interface{}) interface{} { <-holdTasks; return nil }, nil, nil)
	}
	// release the tasks
	close(holdTasks)

	// make sure the EnqueueBacklogis returning err
	for x := 0; x < 10; x++ {
		err := verificationPool.EnqueueBacklog(context.Background(),
			func(arg interface{}) interface{} { return nil }, nil, nil)
		require.Error(t, err, fmt.Sprintf("x = %d", x))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cache := MakeVerifiedTransactionCache(50000)

	stxnChan := make(chan *UnverifiedElement)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedElement)
	sv, err := MakeStreamVerifier(stxnChan, resultChan, droppedChan, &DummyLedgerForSignature{}, verificationPool, cache)
	require.NoError(t, err)
	sv.Start(ctx)

	errChan := make(chan error)

	var badSigResultCounter int
	var goodSigResultCounter int

	wg.Add(1)
	go processResults(ctx, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	// When the exec pool shuts down, the batch verifier should gracefully stop
	// cancel the context so that the test can terminate
	wg.Add(1)
	go func() {
		defer wg.Done()
		sv.WaitForStop()
		cancel()
	}()

	wg.Add(1)
	// send txn groups to be verified
	go func() {
		defer wg.Done()
		for _, tg := range txnGroups {
			select {
			case <-ctx.Done():
				break
			case stxnChan <- &UnverifiedElement{TxnGroup: tg, BacklogMessage: nil}:
			}
		}
	}()
	for err := range errChan {
		require.ErrorIs(t, err, errShuttingDownError)
	}
	require.Contains(t, logBuffer.String(), "addVerificationTaskToThePoolNow: EnqueueBacklog returned an error and StreamVerifier will stop: context canceled")
}

// TestStreamVerifierRestart tests what happens when the context is canceled
func TestStreamVerifierRestart(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 1000
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, 1, 0, 0.5)

	// prepare the stream verifier
	numOfTxnGroups := len(txnGroups)
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	cache := MakeVerifiedTransactionCache(50)

	stxnChan := make(chan *UnverifiedElement)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedElement)

	ctx, cancel := context.WithCancel(context.Background())
	sv, err := MakeStreamVerifier(stxnChan, resultChan, droppedChan, &DummyLedgerForSignature{}, verificationPool, cache)
	require.NoError(t, err)
	sv.Start(ctx)

	errChan := make(chan error)

	var badSigResultCounter int
	var goodSigResultCounter int

	ctx2, cancel2 := context.WithCancel(context.Background())

	wg := sync.WaitGroup{}
	wg.Add(1)
	go processResults(ctx2, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	wg.Add(1)
	// send txn groups to be verified
	go func() {
		defer wg.Done()
		for i, tg := range txnGroups {
			if (i+1)%10 == 0 {
				cancel()
				sv.WaitForStop()
				ctx, cancel = context.WithCancel(context.Background())
				sv.Start(ctx)
			}
			select {
			case <-ctx2.Done():
				break
			case stxnChan <- &UnverifiedElement{TxnGroup: tg, BacklogMessage: nil}:
			}
		}
		cancel()
	}()
	for err := range errChan {
		require.ErrorIs(t, err, errShuttingDownError)
	}
	wg.Wait()
	sv.WaitForStop()
	cancel2() // not necessary, but the golint will want to see this
}

// TestBlockWatcher runs multiple goroutines to check the concurency and correctness of the block watcher
func TestStreamVerifierBlockWatcher(t *testing.T) {
	partitiontest.PartitionTest(t)
	blkHdr := createDummyBlockHeader()
	nbw := MakeNewBlockWatcher(blkHdr)
	startingRound := blkHdr.Round

	wg := sync.WaitGroup{}
	count := 100

	wg.Add(1)
	go func() {
		defer wg.Done()
		for x := 0; x < 100; x++ {
			blkHdr.Round++
			nbw.OnNewBlock(bookkeeping.Block{BlockHeader: blkHdr}, ledgercore.StateDelta{})
			time.Sleep(10 * time.Millisecond)
			nbw.OnNewBlock(bookkeeping.Block{BlockHeader: blkHdr}, ledgercore.StateDelta{})
		}
	}()

	bhStore := make(map[basics.Round]*bookkeeping.BlockHeader)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			bh := nbw.getBlockHeader()
			bhStore[bh.Round] = bh
			if bh.Round == startingRound+10 {
				break
			}
		}
	}()
	wg.Wait()
	bh := nbw.getBlockHeader()
	require.Equal(t, uint64(startingRound)+uint64(count), uint64(bh.Round))
	// There should be no inconsistency after new blocks are added
	for r, bh := range bhStore {
		require.Equal(t, r, bh.Round)
	}
}

func getSaturatedExecPool(t *testing.T) (execpool.BacklogPool, chan interface{}) {
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	_, buffLen := verificationPool.BufferSize()

	// make the buffer full to control when the tasks get executed
	holdTasks := make(chan interface{})
	for x := 0; x < buffLen+runtime.NumCPU()+1; x++ {
		verificationPool.EnqueueBacklog(context.Background(),
			func(arg interface{}) interface{} {
				<-holdTasks
				return nil
			}, nil, nil)
	}
	return verificationPool, holdTasks
}

// TestStreamVerifierCtxCancel tests the termination when the ctx is canceled
// To make sure that the batchingLoop is still working on a batch when the
// ctx is cancled, this test first saturates the exec pool buffer, then
// sends a txn and immediately cancels the ctx so that the batch is not
// passed to the exec pool yet, but is in batchingLoop
func TestStreamVerifierCtxCancel(t *testing.T) {
	partitiontest.PartitionTest(t)

	verificationPool, holdTasks := getSaturatedExecPool(t)
	defer verificationPool.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	cache := MakeVerifiedTransactionCache(50)
	stxnChan := make(chan *UnverifiedElement)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedElement)
	sv, err := MakeStreamVerifier(stxnChan, resultChan, droppedChan, &DummyLedgerForSignature{}, verificationPool, cache)
	require.NoError(t, err)
	sv.Start(ctx)

	var result *VerificationResult
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// no verification tasks should be executed
		// one result should be returned
		result = <-resultChan
	}()

	// send batchSizeBlockLimit after the exec pool buffer is full
	numOfTxns := 1
	txnGroups, _ := getSignedTransactions(numOfTxns, 1, 0, 0.5)
	stxnChan <- &UnverifiedElement{TxnGroup: txnGroups[0], BacklogMessage: nil}
	// cancel the ctx before the sig is sent to the exec pool
	cancel()

	// the main loop should stop after cancel()
	sv.WaitForStop()

	// release the tasks
	close(holdTasks)

	wg.Wait()
	require.ErrorIs(t, result.Err, errShuttingDownError)
}

// TestStreamVerifierCtxCancelPoolQueue tests the termination when the ctx is canceled
// To make sure that the batchingLoop is still working on a batch when the
// ctx is cancled, this test first saturates the exec pool buffer, then
// sends a txn and cancels the ctx after multiple waitForNextTxnDuration
// so that the batch is sent to the pool. Since the pool is saturated,
// the task will be stuck waiting to be queued when the context is canceled
// everything should be gracefully terminated
func TestStreamVerifierCtxCancelPoolQueue(t *testing.T) { //nolint:paralleltest // Not parallel because it depends on the default logger
	partitiontest.PartitionTest(t)

	verificationPool, holdTasks := getSaturatedExecPool(t)

	// check the logged information
	var logBuffer bytes.Buffer
	log := logging.Base()
	log.SetOutput(&logBuffer)
	log.SetLevel(logging.Info)

	ctx, cancel := context.WithCancel(context.Background())
	cache := MakeVerifiedTransactionCache(50)
	stxnChan := make(chan *UnverifiedElement)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedElement)
	sv, err := MakeStreamVerifier(stxnChan, resultChan, droppedChan, &DummyLedgerForSignature{}, verificationPool, cache)
	require.NoError(t, err)
	sv.Start(ctx)

	var result *VerificationResult
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			result = <-resultChan
			// at least one errShuttingDownError is expected
			if result.Err != errShuttingDownError {
				continue
			}
			break
		}
	}()

	// send batchSizeBlockLimit after the exec pool buffer is full
	numOfTxns := 1
	txnGroups, _ := getSignedTransactions(numOfTxns, 1, 0, 0.5)

	wg.Add(1)
	// run in separate goroutine because the exec pool is blocked here, and this will not advance
	// until holdTasks are closed
	go func() {
		defer wg.Done()
		for {
			select {
			// Normally, a single txn is sufficient, but the goroutines could be scheduled is such a way that
			// the single transaction slips through and passes the batch verifier before the exec pool shuts down.
			// this happens when close(holdTasks) runs and frees the exec pool, and lets the txns get verified, before
			// verificationPool.Shutdown() executes.
			case stxnChan <- &UnverifiedElement{TxnGroup: txnGroups[0], BacklogMessage: nil}:
			case <-ctx.Done():
				return
			}
		}
	}()
	// cancel the ctx as the sig is not yet sent to the exec pool
	// the test might sporadically fail if between sending the txn above
	// and the cancelation, 2 x waitForNextTxnDuration elapses (10ms)
	time.Sleep(6 * waitForNextTxnDuration)
	go func() {
		// wait a bit before releasing the tasks, so that the verificationPool ctx first gets canceled
		time.Sleep(20 * time.Millisecond)
		close(holdTasks)
	}()
	verificationPool.Shutdown()

	// the main loop should stop before calling cancel() when the exec pool shuts down and returns an error
	sv.WaitForStop()
	cancel()

	wg.Wait()
	require.ErrorIs(t, result.Err, errShuttingDownError)
	require.Contains(t, logBuffer.String(), "addVerificationTaskToThePoolNow: EnqueueBacklog returned an error and StreamVerifier will stop: context canceled")
}

// TestStreamVerifierPostVBlocked tests the behavior when the return channel (result chan) of verified
// transactions is blocked, and checks droppedFromPool counter to confirm the drops
func TestStreamVerifierPostVBlocked(t *testing.T) {
	partitiontest.PartitionTest(t)

	// prepare the stream verifier
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	defer verificationPool.Shutdown()
	errChan := make(chan error)
	var badSigResultCounter int
	var goodSigResultCounter int

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache := MakeVerifiedTransactionCache(50)

	txBacklogSizeMod := txBacklogSize / 20

	stxnChan := make(chan *UnverifiedElement)
	resultChan := make(chan *VerificationResult, txBacklogSizeMod)
	droppedChan := make(chan *UnverifiedElement)
	sv, err := MakeStreamVerifier(stxnChan, resultChan, droppedChan, &DummyLedgerForSignature{}, verificationPool, cache)
	require.NoError(t, err)

	defer close(droppedChan)
	go func() {
		for range droppedChan {
			droppedFromPool.Inc(nil)
		}
	}()

	// start the verifier
	sv.Start(ctx)
	overflow := 3
	// send txBacklogSizeMod + 3 transactions to overflow the result buffer
	numOfTxns := txBacklogSizeMod + overflow
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, 1, 0, 0.5)
	numOfTxnGroups := len(txnGroups)
	for _, tg := range txnGroups {
		stxnChan <- &UnverifiedElement{TxnGroup: tg, BacklogMessage: nil}
	}

	var droppedPool uint64
	// wait until overflow transactions are dropped
	for w := 0; w < 100; w++ {
		droppedPool = droppedFromPool.GetUint64Value()
		if droppedPool >= uint64(overflow) {
			break
		}
		time.Sleep(time.Millisecond * 20)
	}

	require.Equal(t, uint64(overflow), droppedPool)

	wg := sync.WaitGroup{}
	wg.Add(1)
	// make sure the other results are fine
	go processResults(ctx, errChan, resultChan, numOfTxnGroups-overflow, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	for err := range errChan {
		require.ErrorIs(t, err, errShuttingDownError)
		fmt.Println(badTxnGroups)
	}

	// check if more transactions can be accepted
	errChan = make(chan error)

	wg.Add(1)
	// make sure the other results are fine
	txnGroups, badTxnGroups2 := getSignedTransactions(numOfTxns, 1, numOfTxns, 0.5)
	// need to combine these, since left overs from the previous one could still come out
	for b := range badTxnGroups2 {
		badTxnGroups[b] = struct{}{}
	}
	go processResults(ctx, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	for _, tg := range txnGroups {
		stxnChan <- &UnverifiedElement{TxnGroup: tg, BacklogMessage: nil}
	}

	for err := range errChan {
		require.ErrorIs(t, err, errShuttingDownError)
		fmt.Println(badTxnGroups)
	}

	wg.Wait()
}

func TestStreamVerifierMakeStreamVerifierErr(t *testing.T) {
	partitiontest.PartitionTest(t)
	_, err := MakeStreamVerifier(nil, nil, nil, &DummyLedgerForSignature{badHdr: true}, nil, nil)
	require.Error(t, err)
}

// TestStreamVerifierCancelWhenPooled tests the case where the ctx is cancled after the verification
// task is queued to the exec pool and before the task is executed in the pool
func TestStreamVerifierCancelWhenPooled(t *testing.T) {
	partitiontest.PartitionTest(t)
	numOfTxns := 1000
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, 1, 0, 0.5)

	// prepare the stream verifier
	numOfTxnGroups := len(txnGroups)
	execPool := execpool.MakePool(t)
	defer execPool.Shutdown()
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	cache := MakeVerifiedTransactionCache(50)

	stxnChan := make(chan *UnverifiedElement)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedElement)
	ctx, cancel := context.WithCancel(context.Background())
	sv, err := MakeStreamVerifier(stxnChan, resultChan, droppedChan, &DummyLedgerForSignature{}, verificationPool, cache)
	require.NoError(t, err)
	sv.Start(ctx)

	errChan := make(chan error)

	var badSigResultCounter int
	var goodSigResultCounter int

	ctx2, cancel2 := context.WithCancel(context.Background())

	wg := sync.WaitGroup{}
	wg.Add(1)
	go processResults(ctx2, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	wg.Add(1)
	// send txn groups to be verified
	go func() {
		defer wg.Done()
		for _, tg := range txnGroups {
			stxnChan <- &UnverifiedElement{TxnGroup: tg, BacklogMessage: nil}
		}
		// cancel the ctx, and expect at least one task queued to the pool but not yet executed
		cancel()
	}()
	for err := range errChan {
		require.ErrorIs(t, err, errShuttingDownError)
	}
	wg.Wait()
	sv.WaitForStop()
	cancel2() // not necessary, but the golint will want to see this
}
