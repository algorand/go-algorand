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
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
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

func verifyTxnGroup(stxs []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader) error {
	_, err := txnGroup(stxs, contextHdr, nil, nil, nil)
	return err
}

type DummyLedgerForSignature struct {
	badHdr bool
}

func (d *DummyLedgerForSignature) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {
	if d.badHdr {
		return bookkeeping.BlockHeader{}, fmt.Errorf("test error block hdr")
	}
	return createDummyBlockHeader(), nil
}
func (d *DummyLedgerForSignature) GenesisHash() crypto.Digest {
	return crypto.Digest{}
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

func makePQSignedTxn(t *testing.T, firstSeedByte byte) transactions.SignedTxn {
	t.Helper()

	signer, authorizer, pqSig := makePQSigFields(t, firstSeedByte)

	var receiver basics.Address
	receiver[0] = 1
	txn := createPayTransaction(config.Consensus[protocol.ConsensusFuture].MinTxnFee, 40, 60, 1, authorizer, receiver)

	signature, err := signer.Sign(txn)
	require.NoError(t, err)
	pqSig.Signature = signature

	return transactions.SignedTxn{
		Txn:   txn,
		PQsig: pqSig,
	}
}

func makeFalconSigner(t *testing.T, firstSeedByte byte) crypto.FalconSigner {
	t.Helper()

	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	signer, err := crypto.GenerateFalconSigner(seed)
	require.NoError(t, err)

	return signer
}

func makePQSigForTxn(t *testing.T, firstSeedByte byte, txn *transactions.Transaction) (basics.Address, transactions.PQSig) {
	t.Helper()

	signer, authorizer, pqSig := makePQSigFields(t, firstSeedByte)

	var signature []byte
	var err error
	if txn != nil {
		signature, err = signer.Sign(*txn)
		require.NoError(t, err)
	}
	pqSig.Signature = signature

	return authorizer, pqSig
}

func makePQSigFields(t *testing.T, firstSeedByte byte) (crypto.FalconSigner, basics.Address, transactions.PQSig) {
	t.Helper()

	signer := makeFalconSigner(t, firstSeedByte)
	publicKey := signer.PublicKey[:]
	salt, authorizer, err := basics.CanonicalPQAddressSalt(protocol.PQSchemeFalcon1024, publicKey)
	require.NoError(t, err)

	return signer, authorizer, transactions.PQSig{
		Scheme:    protocol.PQSchemeFalcon1024,
		Salt:      salt,
		PublicKey: publicKey,
	}
}

func requireTxGroupErrorReason(t *testing.T, err error, reason TxGroupErrorReason) {
	t.Helper()

	var txGroupErr *TxGroupError
	require.ErrorAs(t, err, &txGroupErr)
	require.Equal(t, reason, txGroupErr.Reason)
}

func createHeartbeatTxn(fv basics.Round, t *testing.T) transactions.SignedTxn {
	secrets, addrs, _ := generateAccounts(1)

	kd := uint64(111)
	lv := fv + 15
	firstID := basics.OneTimeIDForRound(fv, kd)
	lastID := basics.OneTimeIDForRound(lv, kd)
	numBatches := lastID.Batch - firstID.Batch + 1
	id := basics.OneTimeIDForRound(lv, kd)

	seed := committee.Seed{0x33}
	otss := crypto.GenerateOneTimeSignatureSecrets(firstID.Batch, numBatches)

	txn := transactions.Transaction{
		Type: "hb",
		Header: transactions.Header{
			Sender:     addrs[0],
			FirstValid: fv,
			LastValid:  lv,
		},
		HeartbeatTxnFields: &transactions.HeartbeatTxnFields{
			HbProof:       otss.Sign(id, seed).ToHeartbeatProof(),
			HbSeed:        seed,
			HbVoteID:      otss.OneTimeSignatureVerifier,
			HbKeyDilution: kd,
		},
	}

	hb := transactions.SignedTxn{
		Sig: secrets[0].Sign(txn),
		Txn: txn,
	}
	return hb
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

	require.NoError(t, payment.WellFormed(spec, proto), "generateTestObjects generated an invalid payment")
	require.NoError(t, verifyTxnGroup(stxns, blockHeader), "generateTestObjects generated a bad signedtxn")

	stxn2 := payment.Sign(secret)
	require.Equal(t, stxn2.Sig, stxn.Sig, "got two different signatures for the same transaction (our signing function is deterministic)")

	stxn2.MessUpSigForTesting()
	require.Equal(t, stxn.ID(), stxn2.ID(), "changing sig caused txid to change")
	require.Error(t, verifyTxnGroup([]transactions.SignedTxn{stxn2}, blockHeader), "verify succeeded with bad sig")

	require.True(t, crypto.SignatureVerifier(addr).Verify(payment, stxn.Sig), "signature on the transaction is not the signature of the hash of the transaction under the spender's key")
}

func TestTxnValidationEncodeDecode(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signed, _, _ := generateTestObjects(100, 50, 0, 0)

	for _, txn := range signed {
		if verifyTxnGroup([]transactions.SignedTxn{txn}, blockHeader) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}

		x := protocol.Encode(&txn)
		decoded := transactions.SignedTxn{}
		protocol.Decode(x, &decoded)
		if verifyTxnGroup([]transactions.SignedTxn{decoded}, blockHeader) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}
	}
}

func TestTxnValidationPQSig(t *testing.T) {
	partitiontest.PartitionTest(t)

	stxn := makePQSignedTxn(t, 0)
	dummyLedger := DummyLedgerForSignature{}
	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)

	_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
	require.NoError(t, err)

	disabledBlkHdr := createDummyBlockHeader(protocol.ConsensusV41)
	require.False(t, config.Consensus[disabledBlkHdr.CurrentProtocol].EnablePQSchemeFalcon1024)

	_, err = TxnGroup([]transactions.SignedTxn{stxn}, &disabledBlkHdr, nil, &dummyLedger)
	require.ErrorContains(t, err, "pq signature validation failed")
	requireTxGroupErrorReason(t, err, TxGroupErrorReasonSigNotWellFormed)
	require.ErrorContains(t, err, "pq signature scheme not enabled")
}

func TestTxnValidationPQSigWithAuthAddr(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, addrs, _ := generateAccounts(3)
	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)
	dummyLedger := DummyLedgerForSignature{}

	txn := createPayTransaction(config.Consensus[protocol.ConsensusFuture].MinTxnFee, 40, 60, 1, addrs[0], addrs[1])
	pqAuthorizer, pqSig := makePQSigForTxn(t, 8, &txn)

	stxn := transactions.SignedTxn{
		Txn:      txn,
		AuthAddr: pqAuthorizer,
		PQsig:    pqSig,
	}

	_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
	require.NoError(t, err)

	stxn.AuthAddr = basics.Address{}
	_, err = TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
	requireTxGroupErrorReason(t, err, TxGroupErrorReasonSigNotWellFormed)
	require.ErrorContains(t, err, "pq signature authorizer mismatch")
}

func TestTxnValidationEd25519SigWithPQSenderAuthAddr(t *testing.T) {
	partitiontest.PartitionTest(t)

	secrets, addrs, _ := generateAccounts(2)
	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)
	dummyLedger := DummyLedgerForSignature{}

	pqSender, _ := makePQSigForTxn(t, 9, nil)
	txn := createPayTransaction(config.Consensus[protocol.ConsensusFuture].MinTxnFee, 40, 60, 1, pqSender, addrs[1])

	stxn := txn.Sign(secrets[0])
	require.Equal(t, addrs[0], stxn.AuthAddr)

	_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
	require.NoError(t, err)

	stxn.AuthAddr = basics.Address{}
	_, err = TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
	require.Error(t, err)
}

func TestTxnValidationPQSigEncodeDecode(t *testing.T) {
	partitiontest.PartitionTest(t)

	stxn := makePQSignedTxn(t, 1)
	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)
	dummyLedger := DummyLedgerForSignature{}

	encoded := protocol.Encode(&stxn)

	var decoded transactions.SignedTxn
	require.NoError(t, protocol.Decode(encoded, &decoded))
	require.Equal(t, stxn.Txn, decoded.Txn)
	require.True(t, stxn.PQsig.Equal(decoded.PQsig))

	_, err := TxnGroup([]transactions.SignedTxn{decoded}, &blkHdr, nil, &dummyLedger)
	require.NoError(t, err)
}

func TestTxnValidationPQSigRejectsMalformedProof(t *testing.T) {
	partitiontest.PartitionTest(t)

	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)
	dummyLedger := DummyLedgerForSignature{}

	t.Run("public-key", func(t *testing.T) {
		stxn := makePQSignedTxn(t, 2)
		stxn.PQsig.PublicKey = slices.Clone(stxn.PQsig.PublicKey[:len(stxn.PQsig.PublicKey)-1])
		stxn.Txn.Sender = stxn.PQsig.AuthorizerAddress()

		_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
		requireTxGroupErrorReason(t, err, TxGroupErrorReasonSigNotWellFormed)
		require.ErrorContains(t, err, "pq signature validation failed")
	})

	t.Run("signature", func(t *testing.T) {
		stxn := makePQSignedTxn(t, 3)
		stxn.PQsig.Signature = make([]byte, crypto.MaxPQSignatureSize+1)

		_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
		requireTxGroupErrorReason(t, err, TxGroupErrorReasonSigNotWellFormed)
		require.ErrorContains(t, err, "pq signature validation failed")
	})
}

func TestTxnValidationEmptySig(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signed, _, _ := generateTestObjects(100, 50, 0, 0)

	for _, txn := range signed {
		if verifyTxnGroup([]transactions.SignedTxn{txn}, blockHeader) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}

		txn.Sig = crypto.Signature{}
		txn.Msig = crypto.MultisigSig{}
		txn.Lsig = transactions.LogicSig{}
		if verifyTxnGroup([]transactions.SignedTxn{txn}, blockHeader) == nil {
			t.Errorf("transaction %#v verified without sig", txn)
		}
	}
}

func TestTxnValidationStateProof(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

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
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
	}

	err := verifyTxnGroup([]transactions.SignedTxn{stxn}, blockHeader)
	require.NoError(t, err, "state proof txn %#v did not verify", stxn)

	stxn2 := stxn
	stxn2.Txn.Type = protocol.PaymentTx
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	err = verifyTxnGroup([]transactions.SignedTxn{stxn2}, blockHeader)
	require.Error(t, err, "payment txn %#v verified from StateProofSender", stxn2)

	secret := keypair()
	stxn2 = stxn
	stxn2.Txn.Header.Sender = basics.Address(secret.SignatureVerifier)
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	stxn2 = stxn2.Txn.Sign(secret)
	err = verifyTxnGroup([]transactions.SignedTxn{stxn2}, blockHeader)
	require.Error(t, err, "state proof txn %#v verified from non-StateProofSender", stxn2)

	// state proof txns are not allowed to have non-zero values for many fields
	stxn2 = stxn
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	err = verifyTxnGroup([]transactions.SignedTxn{stxn2}, blockHeader)
	require.Error(t, err, "state proof txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.Header.Note = []byte{'A'}
	err = verifyTxnGroup([]transactions.SignedTxn{stxn2}, blockHeader)
	require.Error(t, err, "state proof txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.Lease[0] = 1
	err = verifyTxnGroup([]transactions.SignedTxn{stxn2}, blockHeader)
	require.Error(t, err, "state proof txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.RekeyTo = basics.Address(secret.SignatureVerifier)
	err = verifyTxnGroup([]transactions.SignedTxn{stxn2}, blockHeader)
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
		verifyTxnGroup([]transactions.SignedTxn{st}, blockHeader)
	}
}

func TestTxnGroupWithTracer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// In all cases, a group of three transactions is tested. They are:
	//   1. A payment transaction from a LogicSig (program1)
	//   2. An app call from a normal account
	//   3. An app call from a LogicSig (program2)

	testCases := []struct {
		name           string
		program1       string
		program2       string
		expectedError  string
		expectedEvents []mocktracer.Event
	}{
		{
			name: "both approve",
			program1: `#pragma version 6
pushint 1`,
			program2: `#pragma version 6
pushbytes "test"
pop
pushint 1`,
			expectedEvents: mocktracer.FlattenEvents([][]mocktracer.Event{
				{
					mocktracer.BeforeProgram(logic.ModeSig),                  // first txn start
					mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(false), // first txn LogicSig: 1 op
					mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultPass), // first txn end
					// nothing for second txn (not signed with a LogicSig)
					mocktracer.BeforeProgram(logic.ModeSig), // third txn start
				},
				mocktracer.OpcodeEvents(3, false), // third txn LogicSig: 3 ops
				{
					mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultPass), // third txn end
				},
			}),
		},
		{
			name: "approve then reject",
			program1: `#pragma version 6
pushint 1`,
			program2: `#pragma version 6
pushbytes "test"
pop
pushint 0`,
			expectedError: "rejected by logic",
			expectedEvents: mocktracer.FlattenEvents([][]mocktracer.Event{
				{
					mocktracer.BeforeProgram(logic.ModeSig),                  // first txn start
					mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(false), // first txn LogicSig: 1 op
					mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultPass), // first txn end
					// nothing for second txn (not signed with a LogicSig)
					mocktracer.BeforeProgram(logic.ModeSig), // third txn start
				},
				mocktracer.OpcodeEvents(3, false), // third txn LogicSig: 3 ops
				{
					mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultReject), // third txn end
				},
			}),
		},
		{
			name: "approve then error",
			program1: `#pragma version 6
pushint 1`,
			program2: `#pragma version 6
pushbytes "test"
pop
err
pushbytes "test2"
pop`,
			expectedError: "rejected by logic err=err opcode executed",
			expectedEvents: mocktracer.FlattenEvents([][]mocktracer.Event{
				{
					mocktracer.BeforeProgram(logic.ModeSig),                  // first txn start
					mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(false), // first txn LogicSig: 1 op
					mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultPass), // first txn end
					// nothing for second txn (not signed with a LogicSig)
					mocktracer.BeforeProgram(logic.ModeSig), // third txn start
				},
				mocktracer.OpcodeEvents(3, true), // third txn LogicSig: 3 ops
				{
					mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultError), // third txn end
				},
			}),
		},
		{
			name: "reject then approve",
			program1: `#pragma version 6
pushint 0`,
			program2: `#pragma version 6
pushbytes "test"
pop
pushint 1`,
			expectedError: "rejected by logic",
			expectedEvents: []mocktracer.Event{
				mocktracer.BeforeProgram(logic.ModeSig),                  // first txn start
				mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(false), // first txn LogicSig: 1 op
				mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultReject), // first txn end
				// execution stops at rejection
			},
		},
		{
			name: "error then approve",
			program1: `#pragma version 6
err`,
			program2: `#pragma version 6
pushbytes "test"
pop
pushint 1`,
			expectedError: "rejected by logic err=err opcode executed",
			expectedEvents: []mocktracer.Event{
				mocktracer.BeforeProgram(logic.ModeSig),                 // first txn start
				mocktracer.BeforeOpcode(), mocktracer.AfterOpcode(true), // first txn LogicSig: 1 op
				mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultError), // first txn end
				// execution stops at error
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			proto := config.Consensus[protocol.ConsensusCurrentVersion]

			account := keypair()
			accountAddr := basics.Address(account.SignatureVerifier)

			ops1, err := logic.AssembleString(testCase.program1)
			require.NoError(t, err)
			program1Bytes := ops1.Program
			program1Addr := basics.Address(logic.HashProgram(program1Bytes))

			ops2, err := logic.AssembleString(testCase.program2)
			require.NoError(t, err)
			program2Bytes := ops2.Program
			program2Addr := basics.Address(logic.HashProgram(program2Bytes))

			// This app program shouldn't be invoked during this test
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
						Logic: program1Bytes,
					},
					Txn: lsigPay.Txn(),
				},
				normalSigAppCall.Txn().Sign(account),
				{
					Lsig: transactions.LogicSig{
						Logic: program2Bytes,
					},
					Txn: lsigAppCall.Txn(),
				},
			}

			mockTracer := &mocktracer.Tracer{}
			_, err = TxnGroupWithTracer(txgroup, blockHeader, nil, logic.NoHeaderLedger{}, mockTracer)

			if len(testCase.expectedError) != 0 {
				require.ErrorContains(t, err, testCase.expectedError)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, testCase.expectedEvents, mockTracer.Events)
		})
	}
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
	paysetGroupDuration := time.Since(startPaysetGroupsTime)

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
			actualDuration := time.Since(startPaysetGroupsTime)
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
		b.N = 2000 //nolint:staticcheck // intentionally setting b.N
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

func TestLsigSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	secrets, addresses, _ := generateAccounts(2)

	execPool := execpool.MakePool(t)
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	// From consensus version 18, we have lsigs with a maximum size of 1000 bytes.
	// We need to use pragma 1 for teal in v18
	pragma := uint(1)
	consensusVersionLegacy := protocol.ConsensusV18
	consensusVersionPooled := protocol.ConsensusV41
	consensusVersionBigLogicSig := protocol.ConsensusFuture
	maxBigLogicSigSize := uint(config.Consensus[consensusVersionBigLogicSig].MaxAbsoluteLogicSigProgramSize)

	// We will do tests based on a transaction group of 2 payment transactions,
	// the first signed by a lsig and the second a vanilla payment transaction.
	testCases := []struct {
		consensusVersion protocol.ConsensusVersion
		lsigSize         uint
		success          bool
	}{
		{consensusVersionLegacy, 1000, true},
		{consensusVersionLegacy, 1001, false},
		{consensusVersionPooled, 2000, true},
		{consensusVersionPooled, 2001, false},
		{consensusVersionBigLogicSig, maxBigLogicSigSize, true},
		{consensusVersionBigLogicSig, maxBigLogicSigSize + 1, false},
	}

	// PaysetGroups exercises signature, LogicSig evaluation, and size checks. It
	// does not run ledger fee checks, so we are just paying the minimum fee here,
	// even if it might not be enough for the larger lsigs.
	blkHdr := createDummyBlockHeader()
	for _, test := range testCases {
		blkHdr.UpgradeState.CurrentProtocol = test.consensusVersion

		lsig, err := txntest.GenerateUnsaltedProgramOfSize(test.lsigSize, pragma)
		require.NoError(t, err)

		lsigPay := txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   basics.Address(logic.HashProgram(lsig)),
			Receiver: addresses[0],
			Fee:      config.Consensus[test.consensusVersion].MinTxnFee,
		}

		vanillaPay := txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   addresses[0],
			Receiver: addresses[1],
			Fee:      config.Consensus[test.consensusVersion].MinTxnFee,
		}

		group := txntest.Group(&lsigPay, &vanillaPay)
		group[0].Lsig = transactions.LogicSig{
			Logic: lsig,
		}
		group[1].Sig = secrets[0].Sign(group[1].Txn)

		err = PaysetGroups(context.Background(), [][]transactions.SignedTxn{group}, blkHdr, verificationPool, MakeVerifiedTransactionCache(50000), &DummyLedgerForSignature{})
		if test.success {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
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
	require.ErrorContains(t, err, "has no sig")
	txnGroups[0][0].Sig = tmpSig

	///// Sig + multiSig
	txnGroups[0][0].Msig.Subsigs = make([]crypto.MultisigSubsig, 1)
	txnGroups[0][0].Msig.Subsigs[0] = crypto.MultisigSubsig{
		Key: crypto.PublicKey{0x1},
		Sig: crypto.Signature{0x2},
	}
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
	require.ErrorContains(t, err, errTxnSigNotWellFormed.Error())
	txnGroups[0][0].Msig.Subsigs = nil

	///// Sig + logic
	txnGroups[0][0].Lsig.Logic = op.Program
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
	require.ErrorContains(t, err, errTxnSigNotWellFormed.Error())
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
	require.ErrorContains(t, err, errTxnSigNotWellFormed.Error())
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
	require.ErrorContains(t, err, "should have only one type of delegation signature")
	txnGroups[0][0].Lsig.Msig.Subsigs = nil

	/////  logic with sig and LMsig
	txnGroups[0][0].Lsig.LMsig.Subsigs = make([]crypto.MultisigSubsig, 1)
	txnGroups[0][0].Lsig.LMsig.Subsigs[0] = crypto.MultisigSubsig{
		Key: crypto.PublicKey{0x1},
		Sig: crypto.Signature{0x2},
	}
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
	require.ErrorContains(t, err, "should have only one type of delegation signature")
	txnGroups[0][0].Lsig.Sig = crypto.Signature{}
	txnGroups[0][0].Lsig.LMsig.Subsigs = nil

	/////  logic with Msig and LMsig
	txnGroups[0][0].Lsig.Msig.Subsigs = make([]crypto.MultisigSubsig, 1)
	txnGroups[0][0].Lsig.Msig.Subsigs[0] = crypto.MultisigSubsig{
		Key: crypto.PublicKey{0x1},
		Sig: crypto.Signature{0x2},
	}
	txnGroups[0][0].Lsig.LMsig.Subsigs = make([]crypto.MultisigSubsig, 1)
	txnGroups[0][0].Lsig.LMsig.Subsigs[0] = crypto.MultisigSubsig{
		Key: crypto.PublicKey{0x3},
		Sig: crypto.Signature{0x4},
	}
	_, err = TxnGroup(txnGroups[0], &blkHdr, nil, &dummyLedger)
	require.ErrorContains(t, err, "should have only one type of delegation signature")

}

func TestTxnGroupPQSigMixedSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)

	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)
	dummyLedger := DummyLedgerForSignature{}

	op, err := logic.AssembleString("int 1")
	require.NoError(t, err)

	t.Run("empty-pq-no-other-signature", func(t *testing.T) {
		stxn := makePQSignedTxn(t, 4)
		stxn.PQsig = transactions.PQSig{}

		_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
		require.ErrorIs(t, err, errTxnSigHasNoSig)
		requireTxGroupErrorReason(t, err, TxGroupErrorReasonHasNoSig)
	})

	t.Run("pq-plus-sig", func(t *testing.T) {
		stxn := makePQSignedTxn(t, 5)
		stxn.Sig = keypair().Sign(stxn.Txn)

		_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
		require.ErrorIs(t, err, errTxnSigNotWellFormed)
		requireTxGroupErrorReason(t, err, TxGroupErrorReasonSigNotWellFormed)
	})

	t.Run("pq-plus-msig", func(t *testing.T) {
		stxn := makePQSignedTxn(t, 6)
		stxn.Msig.Subsigs = []crypto.MultisigSubsig{{
			Key: crypto.PublicKey{0x1},
			Sig: crypto.Signature{0x2},
		}}

		_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
		require.ErrorIs(t, err, errTxnSigNotWellFormed)
		requireTxGroupErrorReason(t, err, TxGroupErrorReasonSigNotWellFormed)
	})

	t.Run("pq-plus-lsig", func(t *testing.T) {
		stxn := makePQSignedTxn(t, 7)
		stxn.Lsig.Logic = op.Program

		_, err := TxnGroup([]transactions.SignedTxn{stxn}, &blkHdr, nil, &dummyLedger)
		require.ErrorIs(t, err, errTxnSigNotWellFormed)
		requireTxGroupErrorReason(t, err, TxGroupErrorReasonSigNotWellFormed)
	})
}

func generateTransactionGroups(maxGroupSize int, signedTxns []transactions.SignedTxn,
	secrets []*crypto.SignatureSecrets, addrs []basics.Address) [][]transactions.SignedTxn {
	addrToSecret := make(map[basics.Address]*crypto.SignatureSecrets)
	for i, addr := range addrs {
		addrToSecret[addr] = secrets[i]
	}

	txnGroups := make([][]transactions.SignedTxn, 0, len(signedTxns))
	for i := 0; i < len(signedTxns); {
		txnsInGroup := min(rand.Intn(protoMaxGroupSize-1)+1, maxGroupSize)
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

// TestTxnHeartbeat makes sure that a heartbeat transaction is valid (and added
// to the cache) only if the normal outer signature is valid AND the inner
// HbProof is valid.
func TestTxnHeartbeat(t *testing.T) {
	partitiontest.PartitionTest(t)

	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)

	txnGroups := make([][]transactions.SignedTxn, 2) // verifyGroup requires at least 2
	for i := 0; i < len(txnGroups); i++ {
		txnGroups[i] = make([]transactions.SignedTxn, 1)
		txnGroups[i][0] = createHeartbeatTxn(blkHdr.Round-1, t)
	}
	breakSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Sig[0]++
	}
	restoreSignatureFunc := func(txn *transactions.SignedTxn) {
		txn.Sig[0]--
	}
	// This shows the outer signature must be correct
	verifyGroup(t, txnGroups, &blkHdr, breakSignatureFunc, restoreSignatureFunc, crypto.ErrBatchHasFailedSigs.Error())

	breakHbProofFunc := func(txn *transactions.SignedTxn) {
		txn.Txn.HeartbeatTxnFields.HbProof.Sig[0]++
	}
	restoreHbProofFunc := func(txn *transactions.SignedTxn) {
		txn.Txn.HeartbeatTxnFields.HbProof.Sig[0]--
	}
	// This shows the inner signature must be correct
	verifyGroup(t, txnGroups, &blkHdr, breakHbProofFunc, restoreHbProofFunc, crypto.ErrBatchHasFailedSigs.Error())
}

// TestTxnGroupCacheUpdateRejLogic test makes sure that a payment transaction contains a logic (and no signature)
// is valid (and added to the cache) only if logic passes
func TestTxnGroupCacheUpdateRejLogic(t *testing.T) {
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

	testVersions := []protocol.ConsensusVersion{protocol.ConsensusV40, protocol.ConsensusFuture}
	for _, consensusVer := range testVersions {
		t.Run(string(consensusVer), func(t *testing.T) {
			useLMsig := config.Consensus[consensusVer].LogicSigLMsig
			testTxnGroupCacheUpdateLogicWithMultiSig(t, consensusVer, useLMsig)
		})
	}
}

func testTxnGroupCacheUpdateLogicWithMultiSig(t *testing.T, consensusVer protocol.ConsensusVersion, useLMsig bool) {
	secrets, _, pks, multiAddress := generateMultiSigAccounts(t, 30)
	blkHdr := createDummyBlockHeader(consensusVer)

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
		var program crypto.Hashable
		if useLMsig {
			program = logic.MultisigProgram{Addr: crypto.Digest(multiAddress[s]), Program: op.Program}
		} else {
			program = logic.Program(op.Program)
		}
		// create multi sig that 2 out of 3 has signed the txn
		var sigs [2]crypto.MultisigSig
		for j := 0; j < 2; j++ {
			msig, err := crypto.MultisigSign(program, crypto.Digest(multiAddress[s]), 1, 2, pks[3*s:3*s+3], *secrets[3*s+j])
			require.NoError(t, err)
			sigs[j] = msig
		}
		msig, err := crypto.MultisigAssemble(sigs[:])
		require.NoError(t, err)
		if useLMsig {
			signedTxn[i].Lsig.LMsig = msig
		} else {
			signedTxn[i].Lsig.Msig = msig
		}
	}

	txnGroups := make([][]transactions.SignedTxn, len(signedTxn))
	for i := 0; i < len(txnGroups); i++ {
		txnGroups[i] = make([]transactions.SignedTxn, 1)
		txnGroups[i][0] = signedTxn[i]
	}

	breakSignatureFunc := func(txn *transactions.SignedTxn) {
		if useLMsig {
			txn.Lsig.LMsig.Subsigs[0].Sig[0]++
		} else {
			txn.Lsig.Msig.Subsigs[0].Sig[0]++
		}
	}
	restoreSignatureFunc := func(txn *transactions.SignedTxn) {
		if useLMsig {
			txn.Lsig.LMsig.Subsigs[0].Sig[0]--
		} else {
			txn.Lsig.Msig.Subsigs[0].Sig[0]--
		}
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

func createDummyBlockHeader(optVer ...protocol.ConsensusVersion) bookkeeping.BlockHeader {
	// Most tests in this file were written to use current.  Future is probably
	// the better test, but I don't want to make that choice now, so optVer.
	proto := protocol.ConsensusCurrentVersion
	if len(optVer) > 0 {
		proto = optVer[0]
	}
	return bookkeeping.BlockHeader{
		Round:       50,
		GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: proto,
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

	dummyLedger := DummyLedgerForSignature{}
	_, err := TxnGroup(txnGroups[0], blkHdr, cache, &dummyLedger)
	require.ErrorContains(t, err, errorString)

	// The txns should not be in the cache
	unverifiedGroups := cache.GetUnverifiedTransactionGroups(txnGroups[:1], spec, blkHdr.CurrentProtocol)
	require.Len(t, unverifiedGroups, 1)

	unverifiedGroups = cache.GetUnverifiedTransactionGroups(txnGroups[:2], spec, blkHdr.CurrentProtocol)
	require.Len(t, unverifiedGroups, 2)

	_, err = TxnGroup(txnGroups[1], blkHdr, cache, &dummyLedger)
	require.NoError(t, err)

	// Only the second txn should be in the cache
	unverifiedGroups = cache.GetUnverifiedTransactionGroups(txnGroups[:2], spec, blkHdr.CurrentProtocol)
	require.Len(t, unverifiedGroups, 1)

	restoreSig(&txnGroups[0][0])

	_, err = TxnGroup(txnGroups[0], blkHdr, cache, &dummyLedger)
	require.NoError(t, err)

	// Both transactions should be in the cache
	unverifiedGroups = cache.GetUnverifiedTransactionGroups(txnGroups[:2], spec, blkHdr.CurrentProtocol)
	require.Len(t, unverifiedGroups, 0)

	cache = MakeVerifiedTransactionCache(1000)
	// Break a random signature
	txgIdx := rand.Intn(len(txnGroups))
	txIdx := rand.Intn(len(txnGroups[txgIdx]))
	breakSig(&txnGroups[txgIdx][txIdx])

	numFailed := 0

	// Add them to the cache by verifying them
	for _, txng := range txnGroups {
		_, err = TxnGroup(txng, blkHdr, cache, &dummyLedger)
		if err != nil {
			require.ErrorContains(t, err, errorString)
			numFailed++
		}
	}
	require.Equal(t, 1, numFailed)

	// Only one transaction should not be in cache
	unverifiedGroups = cache.GetUnverifiedTransactionGroups(txnGroups, spec, blkHdr.CurrentProtocol)
	require.Len(t, unverifiedGroups, 1)

	require.Equal(t, unverifiedGroups[0], txnGroups[txgIdx])
	restoreSig(&txnGroups[txgIdx][txIdx])
}

func BenchmarkTxn(b *testing.B) {
	if b.N < 2000 {
		b.N = 2000 //nolint:staticcheck // intentionally setting b.N
	}
	_, signedTxn, secrets, addrs := generateTestObjects(b.N, 20, 0, 50)
	blk := bookkeeping.Block{BlockHeader: createDummyBlockHeader()}
	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

	b.ResetTimer()
	for _, txnGroup := range txnGroups {
		err := verifyTxnGroup(txnGroup, &blk.BlockHeader)
		require.NoError(b, err)
	}
	b.StopTimer()
}

// TestLogicSigMultisigValidation verifies that signatures are properly validated
// in different contexts (single-sig vs multisig, different multisig addresses).
func TestLogicSigMultisigValidation(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Run("v40", func(t *testing.T) { testLogicSigMultisigValidation(t, protocol.ConsensusV40, false) })
	t.Run("v41", func(t *testing.T) { testLogicSigMultisigValidation(t, protocol.ConsensusV41, true) })
	t.Run("future", func(t *testing.T) { testLogicSigMultisigValidation(t, protocol.ConsensusFuture, true) })
}

func TestBigLogicSigProgramSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	v18 := config.Consensus[protocol.ConsensusV18]
	v41 := config.Consensus[protocol.ConsensusV41]
	vFuture := config.Consensus[protocol.ConsensusFuture]

	makeProgram := func(proto config.ConsensusParams, minSize int) []byte {
		// GenerateUnsaltedProgramOfSize needs at least 5 bytes for a valid
		// always-succeeding program.
		if minSize < 5 {
			minSize = 5
		}
		program, err := txntest.GenerateUnsaltedProgramOfSize(uint(minSize), uint(proto.LogicSigVersion))
		require.NoError(t, err)
		return program
	}

	makeLogicSigTxnForReceiver := func(program []byte, args [][]byte, receiver basics.Address) transactions.SignedTxn {
		stxn := txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   basics.Address(logic.HashProgram(program)),
			Receiver: receiver,
			// we are not testing fee validation here, so min fee is enough even when program is big
			Fee:    config.Consensus[protocol.ConsensusFuture].MinTxnFee,
			Amount: uint64(1000),
		}.SignedTxn()
		stxn.Lsig = transactions.LogicSig{
			Logic: program,
			Args:  args,
		}
		return stxn
	}
	makeLogicSigTxn := func(program []byte, args [][]byte) transactions.SignedTxn {
		return makeLogicSigTxnForReceiver(program, args, basics.Address{1})
	}
	makeArgs := func(size int) [][]byte {
		args := make([][]byte, 0, (size+transactions.MaxLogicSigArgSize-1)/transactions.MaxLogicSigArgSize)
		for size > 0 {
			argSize := min(size, transactions.MaxLogicSigArgSize)
			args = append(args, make([]byte, argSize))
			size -= argSize
		}
		return args
	}

	verifyGroupForProtocol := func(consensusVer protocol.ConsensusVersion, group []transactions.SignedTxn) error {
		blkHdr := createDummyBlockHeader(consensusVer)
		_, err := TxnGroup(group, &blkHdr, nil, &DummyLedgerForSignature{})
		return err
	}
	makeSignedTxn := func(proto config.ConsensusParams) transactions.SignedTxn {
		secrets := keypair()
		sender := basics.Address(secrets.SignatureVerifier)
		txn := txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender,
			Receiver: basics.Address{1},
			Fee:      proto.MinTxnFee,
			Amount:   uint64(1000),
		}.Txn()
		return transactions.SignedTxn{
			Txn: txn,
			Sig: secrets.Sign(txn),
		}
	}
	makeSignedTxnWithOrphanLsig := func(proto config.ConsensusParams, lsig transactions.LogicSig) transactions.SignedTxn {
		stxn := makeSignedTxn(proto)
		stxn.Lsig = lsig
		return stxn
	}
	makeSignedTxnWithOrphanArgs := func(proto config.ConsensusParams, args [][]byte) transactions.SignedTxn {
		return makeSignedTxnWithOrphanLsig(proto, transactions.LogicSig{Args: args})
	}

	t.Run("v18: singleton still limited by legacy size pool", func(t *testing.T) {
		program := makeProgram(v18, int(v18.LogicSigMaxSize)+1)
		err := verifyGroupForProtocol(protocol.ConsensusV18, []transactions.SignedTxn{makeLogicSigTxn(program, nil)})
		require.ErrorContains(t, err, "more than the available pool")
	})

	t.Run("v18: orphan LogicSig args on signed txn are ignored", func(t *testing.T) {
		stxn := makeSignedTxnWithOrphanArgs(v18, [][]byte{make([]byte, int(v18.LogicSigMaxSize)+1)})

		err := verifyGroupForProtocol(protocol.ConsensusV18, []transactions.SignedTxn{stxn})
		require.NoError(t, err)
	})

	t.Run("v41: orphan LogicSig args on signed txn use the current pool", func(t *testing.T) {
		stxn := makeSignedTxnWithOrphanArgs(v41, [][]byte{make([]byte, int(v41.LogicSigMaxSize)+500)})

		err := verifyGroupForProtocol(protocol.ConsensusV41, []transactions.SignedTxn{stxn})
		require.ErrorContains(t, err, "more than the available pool")
	})

	t.Run("v41: orphan LogicSig args on signed txn can use size pooling", func(t *testing.T) {
		stxn := makeSignedTxnWithOrphanArgs(v41, [][]byte{make([]byte, int(v41.LogicSigMaxSize)+500)})

		err := verifyGroupForProtocol(protocol.ConsensusV41, []transactions.SignedTxn{
			stxn,
			makeSignedTxn(v41),
		})
		require.NoError(t, err)
	})

	t.Run("vFuture: orphan LogicSig args on signed txn are rejected", func(t *testing.T) {
		stxn := makeSignedTxnWithOrphanArgs(vFuture, [][]byte{make([]byte, int(vFuture.LogicSigMaxSize))})

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn})
		require.ErrorContains(t, err, "LogicSig fields without LogicSig program")
	})

	t.Run("orphan LogicSig delegation signature on signed txn", func(t *testing.T) {
		lsigSig := crypto.Signature{}
		lsigSig[0] = 1

		tests := []struct {
			name string
			lsig transactions.LogicSig
		}{
			{name: "sig", lsig: transactions.LogicSig{Sig: lsigSig}},
			{name: "msig", lsig: transactions.LogicSig{Msig: crypto.MultisigSig{Version: 1}}},
			{name: "lmsig", lsig: transactions.LogicSig{LMsig: crypto.MultisigSig{Version: 1}}},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				stxn := makeSignedTxnWithOrphanLsig(v18, test.lsig)
				err := verifyGroupForProtocol(protocol.ConsensusV18, []transactions.SignedTxn{stxn})
				require.NoError(t, err)

				stxn = makeSignedTxnWithOrphanLsig(v41, test.lsig)
				err = verifyGroupForProtocol(protocol.ConsensusV41, []transactions.SignedTxn{stxn})
				require.NoError(t, err)

				stxn = makeSignedTxnWithOrphanLsig(vFuture, test.lsig)
				err = verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn})
				require.ErrorContains(t, err, "LogicSig fields without LogicSig program")
			})
		}
	})

	t.Run("v41: singleton cannot exceed current pool without pricing", func(t *testing.T) {
		program := makeProgram(v41, int(v41.LogicSigMaxSize)+1)
		err := verifyGroupForProtocol(protocol.ConsensusV41, []transactions.SignedTxn{makeLogicSigTxn(program, nil)})
		require.ErrorContains(t, err, "more than the available pool")
	})

	t.Run("v41: singleton program and args share the current pool", func(t *testing.T) {
		program := makeProgram(v41, int(v41.LogicSigMaxSize))
		err := verifyGroupForProtocol(protocol.ConsensusV41, []transactions.SignedTxn{
			makeLogicSigTxn(program, [][]byte{make([]byte, int(v41.LogicSigMaxSize))}),
		})
		require.ErrorContains(t, err, "more than the available pool")
	})

	t.Run("v41: ordinary size pooling is still allowed", func(t *testing.T) {
		program := makeProgram(v41, int(v41.LogicSigMaxSize)+1)
		err := verifyGroupForProtocol(protocol.ConsensusV41, []transactions.SignedTxn{
			makeLogicSigTxnForReceiver(program, nil, basics.Address{1}),
			makeLogicSigTxnForReceiver(makeProgram(v41, 0), nil, basics.Address{2}),
		})
		require.NoError(t, err)
	})

	t.Run("vFuture: singleton can use more than one legacy size unit", func(t *testing.T) {
		program := makeProgram(vFuture, int(vFuture.LogicSigMaxSize)+1)
		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{makeLogicSigTxn(program, nil)})
		require.NoError(t, err)
	})

	t.Run("vFuture: LogicSig program cannot exceed absolute limit", func(t *testing.T) {
		program := make([]byte, int(vFuture.MaxAbsoluteLogicSigProgramSize)+1)
		program[0] = byte(vFuture.LogicSigVersion)

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{makeLogicSigTxn(program, nil)})
		require.ErrorContains(t, err, "LogicSig.Logic too long")
	})

	t.Run("vFuture: singleton program and args have independent allowances", func(t *testing.T) {
		program := makeProgram(vFuture, int(vFuture.LogicSigMaxSize))
		args := [][]byte{make([]byte, int(vFuture.LogicSigMaxSize))}

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{makeLogicSigTxn(program, args)})
		require.NoError(t, err)
	})

	t.Run("vFuture: singleton LogicSig args above allowance require size pooling", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		args := [][]byte{make([]byte, int(vFuture.LogicSigMaxSize)+1)}

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{makeLogicSigTxn(program, args)})
		require.ErrorContains(t, err, "more than the available size pool")
	})

	t.Run("vFuture: LogicSig args above allowance can use size pooling", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		args := [][]byte{make([]byte, int(vFuture.LogicSigMaxSize)+1)}

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{
			makeLogicSigTxnForReceiver(program, args, basics.Address{1}),
			makeLogicSigTxnForReceiver(program, nil, basics.Address{2}),
			makeLogicSigTxnForReceiver(program, nil, basics.Address{3}),
		})
		require.NoError(t, err)
	})

	t.Run("vFuture: LogicSig args pool counts args from every LogicSig", func(t *testing.T) {
		program := makeProgram(vFuture, 0)

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{
			makeLogicSigTxnForReceiver(program, [][]byte{make([]byte, int(vFuture.LogicSigMaxSize))}, basics.Address{1}),
			makeLogicSigTxnForReceiver(program, [][]byte{make([]byte, int(vFuture.LogicSigMaxSize)+1)}, basics.Address{2}),
		})
		require.ErrorContains(t, err, "more than the available size pool")
	})

	t.Run("vFuture: LogicSig args above allowance can use declared budget", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		args := makeArgs(int(vFuture.LogicSigMaxSize) + 1)
		stxn := makeLogicSigTxn(program, args)
		stxn.Txn.LogicSigArgsBudget = uint64(stxn.Lsig.ArgsLen())

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn})
		require.NoError(t, err)
	})

	t.Run("vFuture: v12 LogicSig can use args budget", func(t *testing.T) {
		program, err := txntest.GenerateUnsaltedProgramOfSize(5, 12)
		require.NoError(t, err)
		args := makeArgs(int(vFuture.LogicSigMaxSize) + 1)
		stxn := makeLogicSigTxn(program, args)
		stxn.Txn.LogicSigArgsBudget = uint64(stxn.Lsig.ArgsLen())

		err = verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn})
		require.NoError(t, err)
	})

	t.Run("vFuture: budgeted args do not consume the zero-budget args pool", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		unbudgetedArgsSize := 2 * int(vFuture.LogicSigMaxSize)
		unbudgetedStxn := makeLogicSigTxnForReceiver(
			program,
			makeArgs(unbudgetedArgsSize),
			basics.Address{1},
		)
		budgetedStxn := makeLogicSigTxnForReceiver(
			program,
			makeArgs(int(vFuture.LogicSigMaxSize)),
			basics.Address{2},
		)
		budgetedStxn.Txn.LogicSigArgsBudget = uint64(budgetedStxn.Lsig.ArgsLen())

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{unbudgetedStxn, budgetedStxn})
		require.NoError(t, err)
	})

	t.Run("vFuture: zero-budget args remain limited in group with budgeted args", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		unbudgetedStxn := makeLogicSigTxnForReceiver(
			program,
			makeArgs(2*int(vFuture.LogicSigMaxSize)+1),
			basics.Address{1},
		)
		budgetedStxn := makeLogicSigTxnForReceiver(
			program,
			makeArgs(int(vFuture.LogicSigMaxSize)),
			basics.Address{2},
		)
		budgetedStxn.Txn.LogicSigArgsBudget = uint64(budgetedStxn.Lsig.ArgsLen())

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{unbudgetedStxn, budgetedStxn})
		require.ErrorContains(t, err, "more than the available size pool")
	})

	t.Run("vFuture: LogicSig args cannot exceed declared budget", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		args := makeArgs(int(vFuture.LogicSigMaxSize) + 2)
		stxn := makeLogicSigTxn(program, args)
		stxn.Txn.LogicSigArgsBudget = uint64(stxn.Lsig.ArgsLen() - 1)

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn})
		require.ErrorContains(t, err, "exceeds declared budget")
	})

	t.Run("vFuture: LogicSig args budget below allowance is invalid", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		stxn := makeLogicSigTxn(program, nil)
		stxn.Txn.LogicSigArgsBudget = vFuture.LogicSigMaxSize - 1

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn})
		require.ErrorContains(t, err, "below LogicSigMaxSize")
	})

	t.Run("vFuture: LogicSig args budget cannot exceed absolute limit", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		stxn := makeLogicSigTxn(program, nil)
		stxn.Txn.LogicSigArgsBudget = vFuture.MaxAbsoluteLogicSigArgsSize + 1

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn})
		require.ErrorContains(t, err, "exceeds MaxAbsoluteLogicSigArgsSize")
	})

	t.Run("vFuture: LogicSig args budget is rejected on non-LogicSig transaction", func(t *testing.T) {
		stxn := makeSignedTxn(vFuture)
		stxn.Txn.LogicSigArgsBudget = vFuture.LogicSigMaxSize

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn})
		require.ErrorContains(t, err, "only valid on LogicSig")
	})

	t.Run("v41: LogicSig args budget is unsupported", func(t *testing.T) {
		program := makeProgram(v41, 0)
		stxn := makeLogicSigTxn(program, nil)
		stxn.Txn.LogicSigArgsBudget = vFuture.LogicSigMaxSize

		err := verifyGroupForProtocol(protocol.ConsensusV41, []transactions.SignedTxn{stxn})
		require.ErrorContains(t, err, "LogicSigArgsBudget is not supported")
	})

	t.Run("vFuture: budgeted LogicSig args have no explicit group cap", func(t *testing.T) {
		program := makeProgram(vFuture, 0)
		argsSize := int(vFuture.MaxAbsoluteLogicSigArgsSize)
		stxn1 := makeLogicSigTxnForReceiver(program, makeArgs(argsSize), basics.Address{1})
		stxn1.Txn.LogicSigArgsBudget = uint64(argsSize)
		stxn2 := makeLogicSigTxnForReceiver(program, makeArgs(argsSize), basics.Address{2})
		stxn2.Txn.LogicSigArgsBudget = uint64(argsSize)

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{stxn1, stxn2})
		require.NoError(t, err)
	})

	t.Run("vFuture: program bytes can exceed legacy group size pool", func(t *testing.T) {
		program := makeProgram(vFuture, int(vFuture.MaxAbsoluteLogicSigProgramSize))

		err := verifyGroupForProtocol(protocol.ConsensusFuture, []transactions.SignedTxn{
			makeLogicSigTxnForReceiver(program, nil, basics.Address{1}),
			makeLogicSigTxnForReceiver(program, nil, basics.Address{2}),
		})
		require.NoError(t, err)
	})

}

func testLogicSigMultisigValidation(t *testing.T, consensusVer protocol.ConsensusVersion, useLMsig bool) {
	ops, err := logic.AssembleString("int 1")
	require.NoError(t, err)
	program := ops.Program

	// Generate test keys
	secrets := make([]*crypto.SignatureSecrets, 3)
	for i := range secrets {
		var seed crypto.Seed
		crypto.RandBytes(seed[:])
		secrets[i] = crypto.GenerateSignatureSecrets(seed)
	}

	// Helper to create a test transaction
	makeTestTxn := func(sender basics.Address) transactions.SignedTxn {
		return transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:      sender,
					Fee:         basics.MicroAlgos{Raw: 1000},
					FirstValid:  1,
					LastValid:   100,
					GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: basics.Address{},
					Amount:   basics.MicroAlgos{Raw: 1000},
				},
			},
		}
	}

	// Helper to verify a logic sig
	verifyLogicSig := func(t *testing.T, stxn transactions.SignedTxn) error {
		blkHdr := createDummyBlockHeader(consensusVer)
		dummyLedger := DummyLedgerForSignature{}
		groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{stxn}, &blkHdr, &dummyLedger, nil)
		require.NoError(t, err)
		return logicSigVerify(0, groupCtx)
	}

	t.Run("MultisigToSingleSig", func(t *testing.T) {
		pks := []crypto.PublicKey{secrets[0].SignatureVerifier}
		msigAddr, err := crypto.MultisigAddrGen(1, 1, pks)
		require.NoError(t, err)

		// Sign in multisig context
		var msig crypto.MultisigSig
		if useLMsig { // >=v41: use MultisigProgram with address binding
			msig, err = crypto.MultisigSign(logic.MultisigProgram{Addr: msigAddr, Program: program}, msigAddr, 1, 1, pks, *secrets[0])
		} else { // v40: use Program directly
			msig, err = crypto.MultisigSign(logic.Program(program), msigAddr, 1, 1, pks, *secrets[0])
		}
		require.NoError(t, err)

		// Try to use multisig signature as single sig
		stxn := makeTestTxn(basics.Address(secrets[0].SignatureVerifier))
		stxn.Lsig = transactions.LogicSig{
			Logic: program,
			Sig:   msig.Subsigs[0].Sig,
		}

		err = verifyLogicSig(t, stxn)
		if useLMsig {
			require.ErrorContains(t, err, "At least one signature didn't pass verification")
		} else {
			require.NoError(t, err)
		}
	})

	t.Run("SingleSigToMultisig", func(t *testing.T) {
		// Sign as single sig
		singleSig := secrets[0].Sign(logic.Program(program))

		// Create multisig with same key
		pks := []crypto.PublicKey{secrets[0].SignatureVerifier}
		msigAddr, err := crypto.MultisigAddrGen(1, 1, pks)
		require.NoError(t, err)

		// Try to use single sig in multisig
		stxn := makeTestTxn(basics.Address(msigAddr))
		msigWithSingleSig := crypto.MultisigSig{Version: 1, Threshold: 1,
			Subsigs: []crypto.MultisigSubsig{{Key: secrets[0].SignatureVerifier, Sig: singleSig}},
		}

		if useLMsig { // >=v41: use LMsig field
			stxn.Lsig = transactions.LogicSig{Logic: program, LMsig: msigWithSingleSig}
			err = verifyLogicSig(t, stxn)
			require.ErrorContains(t, err, "At least one signature didn't pass verification")
		} else { // v40: use Msig field
			stxn.Lsig = transactions.LogicSig{Logic: program, Msig: msigWithSingleSig}
			err = verifyLogicSig(t, stxn)
			require.NoError(t, err)
		}
	})

	t.Run("CrossMultisigValidation", func(t *testing.T) {
		// Create two different 1-of-2 multisigs
		pks1 := []crypto.PublicKey{secrets[0].SignatureVerifier, secrets[1].SignatureVerifier, secrets[2].SignatureVerifier}
		pks2 := []crypto.PublicKey{secrets[0].SignatureVerifier, secrets[1].SignatureVerifier}

		msigAddr1, err := crypto.MultisigAddrGen(1, 2, pks1)
		require.NoError(t, err)
		msigAddr2, err := crypto.MultisigAddrGen(1, 2, pks2)
		require.NoError(t, err)

		// Sign for each multisig
		var sig1, sig2 crypto.MultisigSig
		if useLMsig { // >=v41: use MultisigProgram with address binding
			sig1, err = crypto.MultisigSign(logic.MultisigProgram{Addr: msigAddr1, Program: program}, msigAddr1, 1, 2, pks1, *secrets[0])
			require.NoError(t, err)
			sig2, err = crypto.MultisigSign(logic.MultisigProgram{Addr: msigAddr2, Program: program}, msigAddr2, 1, 2, pks2, *secrets[1])
			require.NoError(t, err)
		} else { // v40: use Program directly
			sig1, err = crypto.MultisigSign(logic.Program(program), msigAddr1, 1, 2, pks1, *secrets[0])
			require.NoError(t, err)
			sig2, err = crypto.MultisigSign(logic.Program(program), msigAddr2, 1, 2, pks2, *secrets[1])
			require.NoError(t, err)
		}

		// Try to mix signatures from different multisigs
		stxn := makeTestTxn(basics.Address(msigAddr2))
		mixedMsig := crypto.MultisigSig{Version: 1, Threshold: 2,
			Subsigs: []crypto.MultisigSubsig{
				{Key: secrets[0].SignatureVerifier, Sig: sig1.Subsigs[0].Sig}, // from msigAddr1
				{Key: secrets[1].SignatureVerifier, Sig: sig2.Subsigs[1].Sig}, // from msigAddr2
			},
		}

		if useLMsig { // >=v41: use LMsig field
			stxn.Lsig = transactions.LogicSig{Logic: program, LMsig: mixedMsig}
			err = verifyLogicSig(t, stxn)
			require.ErrorContains(t, err, "At least one signature didn't pass verification")
		} else { // v40: use Msig field
			stxn.Lsig = transactions.LogicSig{Logic: program, Msig: mixedMsig}
			err = verifyLogicSig(t, stxn)
			require.NoError(t, err)
		}
	})

	t.Run("DisableMsig", func(t *testing.T) {
		// Run on consensus when Msig is disabled, only LMsig allowed
		if config.Consensus[consensusVer].LogicSigMsig || !config.Consensus[consensusVer].LogicSigLMsig {
			t.Skip("requires LogicSigMsig=false and LogicSigLMsig=true")
		}

		pks := []crypto.PublicKey{secrets[0].SignatureVerifier, secrets[1].SignatureVerifier}
		msigAddr, err := crypto.MultisigAddrGen(1, 2, pks)
		require.NoError(t, err)

		// Sign with address binding
		sig1, err := crypto.MultisigSign(logic.MultisigProgram{Addr: msigAddr, Program: program}, msigAddr, 1, 2, pks, *secrets[0])
		require.NoError(t, err)
		sig2, err := crypto.MultisigSign(logic.MultisigProgram{Addr: msigAddr, Program: program}, msigAddr, 1, 2, pks, *secrets[1])
		require.NoError(t, err)

		msig, err := crypto.MultisigAssemble([]crypto.MultisigSig{sig1, sig2})
		require.NoError(t, err)

		// Create a transaction
		stxn := makeTestTxn(basics.Address(msigAddr))

		// Test with Msig field - should be rejected
		stxn.Lsig = transactions.LogicSig{Logic: program, Msig: msig}
		err = verifyLogicSig(t, stxn)
		require.ErrorContains(t, err, "LogicSig Msig field not supported in this consensus version")

		// Test with LMsig field - should work
		stxn.Lsig = transactions.LogicSig{Logic: program, LMsig: msig}
		err = verifyLogicSig(t, stxn)
		require.NoError(t, err)

		// Test with both fields - should fail
		stxn.Lsig = transactions.LogicSig{Logic: program, Msig: msig, LMsig: msig}
		err = verifyLogicSig(t, stxn)
		require.ErrorContains(t, err, "LogicSig should have only one type of delegation signature")
	})
}

func TestLogicSigMsigBothFlags(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Create a test consensus version with both flags enabled
	consensusVer := protocol.ConsensusCurrentVersion
	testConsensus := config.Consensus[consensusVer]
	testConsensus.LogicSigMsig = true
	testConsensus.LogicSigLMsig = true
	config.Consensus["test-lmsig-flags"] = testConsensus
	defer delete(config.Consensus, "test-lmsig-flags")

	// Simple test program that always approves
	ops, err := logic.AssembleString("int 1")
	require.NoError(t, err)
	program := ops.Program

	// Create test keys
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	secret := crypto.GenerateSignatureSecrets(seed)
	pks := []crypto.PublicKey{secret.SignatureVerifier}

	msigAddr, err := crypto.MultisigAddrGen(1, 1, pks)
	require.NoError(t, err)

	// Sign with both methods
	msig, err := crypto.MultisigSign(logic.Program(program), msigAddr, 1, 1, pks, *secret)
	require.NoError(t, err)

	lmsig, err := crypto.MultisigSign(logic.MultisigProgram{Addr: msigAddr, Program: program}, msigAddr, 1, 1, pks, *secret)
	require.NoError(t, err)

	// Create test transaction
	stxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      basics.Address(msigAddr),
				Fee:         basics.MicroAlgos{Raw: 1000},
				FirstValid:  1,
				LastValid:   100,
				GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: basics.Address{},
				Amount:   basics.MicroAlgos{Raw: 1000},
			},
		},
	}

	// Helper to verify a logic sig
	verifyLogicSig := func() error {
		blkHdr := createDummyBlockHeader("test-lmsig-flags")
		dummyLedger := DummyLedgerForSignature{}
		groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{stxn}, &blkHdr, &dummyLedger, nil)
		require.NoError(t, err)
		return logicSigVerify(0, groupCtx)
	}

	// Test with Msig field only - should work
	stxn.Lsig = transactions.LogicSig{Logic: program, Msig: msig}
	err = verifyLogicSig()
	require.NoError(t, err)

	// Test with LMsig field only - should work
	stxn.Lsig = transactions.LogicSig{Logic: program, LMsig: lmsig}
	err = verifyLogicSig()
	require.NoError(t, err)

	// Test with both fields - should fail
	stxn.Lsig = transactions.LogicSig{Logic: program, Msig: msig, LMsig: lmsig}
	err = verifyLogicSig()
	require.ErrorContains(t, err, "LogicSig should have only one type of delegation signature")
}

func TestAuthAddrSenderDiff(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Run("v41-disabled", func(t *testing.T) { testAuthAddrSenderDiff(t, protocol.ConsensusV41, false) })
	t.Run("future-enabled", func(t *testing.T) { testAuthAddrSenderDiff(t, protocol.ConsensusFuture, true) })
}

func testAuthAddrSenderDiff(t *testing.T, consensusVer protocol.ConsensusVersion, enforceEnabled bool) {
	secrets, addrs, _ := generateAccounts(3)
	sender := addrs[0]
	otherAddr := addrs[1]

	blockHeader := createDummyBlockHeader(consensusVer)
	proto := config.Consensus[consensusVer]

	makeTxn := func() transactions.Transaction {
		return transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      sender,
				Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
				FirstValid:  1,
				LastValid:   100,
				GenesisHash: blockHeader.GenesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: addrs[2],
				Amount:   basics.MicroAlgos{Raw: 1000},
			},
		}
	}

	// Test 1: AuthAddr == Sender
	tx1 := makeTxn()
	stxn := tx1.Sign(secrets[0])
	stxn.AuthAddr = sender
	err := verifyTxnGroup([]transactions.SignedTxn{stxn}, &blockHeader)
	if enforceEnabled {
		require.ErrorContains(t, err, "AuthAddr must be different from Sender",
			"AuthAddr == Sender should be rejected when enforcement is enabled")
	} else {
		require.NoError(t, err,
			"AuthAddr == Sender should be allowed when enforcement is disabled")
	}

	// Test 2: Empty AuthAddr should always be allowed
	tx2 := makeTxn()
	stxn = tx2.Sign(secrets[0])
	stxn.AuthAddr = basics.Address{}
	err = verifyTxnGroup([]transactions.SignedTxn{stxn}, &blockHeader)
	require.NoError(t, err, "empty AuthAddr should always be allowed")

	// Test 3: AuthAddr != Sender should pass the check (legitimate rekeying case)
	// Sign with otherAddr's key to pass signature verification
	tx3 := makeTxn()
	stxn = tx3.Sign(secrets[1]) // Sign with secrets[1] which corresponds to otherAddr
	stxn.AuthAddr = otherAddr
	err = verifyTxnGroup([]transactions.SignedTxn{stxn}, &blockHeader)
	require.NoError(t, err, "AuthAddr != Sender should pass verification (legitimate rekeying)")
}

func TestTxnGroupRecoversPanic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// A non-empty group is required so PrepareGroupContext does not return early before the
	// contextHdr dereference.
	group := []transactions.SignedTxn{{Txn: transactions.Transaction{Type: protocol.PaymentTx}}}

	// A nil BlockHeader makes group preparation panic; TxnGroup must recover it into an error
	groupCtx, err := TxnGroup(group, nil, nil, &DummyLedgerForSignature{})
	require.Nil(t, groupCtx)
	require.ErrorContains(t, err, "panic while verifying transaction group")
}
