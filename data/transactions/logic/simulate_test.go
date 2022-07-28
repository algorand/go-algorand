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

package logic_test

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	. "github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// ==============================
// > Simulation Test Ledger
// ==============================

type SimulationTestLedger struct {
	*Ledger

	hdr bookkeeping.BlockHeader
}

func (sl *SimulationTestLedger) Latest() basics.Round {
	return sl.hdr.Round
}

func (sl *SimulationTestLedger) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {
	if rnd != sl.Latest() {
		err = fmt.Errorf(
			"BlockHdr() evaluator called this function for the wrong round %d, "+
				"latest round is %d",
			rnd, sl.Latest())
		return
	}

	return sl.hdr, nil
}

func (sl *SimulationTestLedger) CheckDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	// Never throw an error during these tests since it's a simulation ledger.
	// In production, the actual ledger method is used.
	return nil
}

func (sl *SimulationTestLedger) CompactCertVoters(rnd basics.Round) (*ledgercore.VotersForRound, error) {
	panic("CompactCertVoters() should not be called in a simulation ledger")
}

func (sl *SimulationTestLedger) GenesisHash() crypto.Digest {
	return sl.hdr.GenesisHash
}

func (sl *SimulationTestLedger) GenesisProto() config.ConsensusParams {
	return config.Consensus[sl.hdr.CurrentProtocol]
}

func (sl *SimulationTestLedger) GetCreatorForRound(round basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	if round != sl.Latest() {
		err = fmt.Errorf(
			"GetCreatorForRound() evaluator called this function for the wrong round %d, "+
				"latest round is %d",
			round, sl.Latest())
		return
	}

	return sl.GetCreator(cidx, ctype)
}

func (sl *SimulationTestLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	assetParams, addr, err := sl.AssetParams(aidx)
	if err != nil {
		return ledgercore.AssetResource{}, err
	}

	assetHolding, err := sl.AssetHolding(addr, aidx)
	if err != nil {
		return ledgercore.AssetResource{}, err
	}

	return ledgercore.AssetResource{
		AssetParams:  &assetParams,
		AssetHolding: &assetHolding,
	}, nil
}

func (sl *SimulationTestLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	if rnd != sl.Latest() {
		return ledgercore.AccountData{}, basics.Round(0), fmt.Errorf(
			"LookupWithoutRewards() evaluator called this function for the wrong round %d, "+
				"latest round is %d",
			rnd, sl.Latest())
	}

	acctData, err := sl.AccountData(addr)
	if err != nil {
		return ledgercore.AccountData{}, basics.Round(0), err
	}

	return acctData, sl.Latest(), nil
}

// ==============================
// > Simulation Test Helpers
// ==============================

func MakeTestClient() libgoal.Client {
	c, err := libgoal.MakeClientFromConfig(libgoal.ClientConfig{
		AlgodDataDir: "NO_DIR",
	}, libgoal.DynamicClient)
	if err != nil {
		panic(err)
	}

	return c
}

func MakeSpecialAccounts() (sink, rewards basics.Address) {
	// irrelevant, but deterministic
	sink, err := basics.UnmarshalChecksumAddress("YTPRLJ2KK2JRFSZZNAF57F3K5Y2KCG36FZ5OSYLW776JJGAUW5JXJBBD7Q")
	if err != nil {
		panic(err)
	}
	rewards, err = basics.UnmarshalChecksumAddress("242H5OXHUEBYCGGWB3CQ6AZAMQB5TMCWJGHCGQOZPEIVQJKOO7NZXUXDQA")
	if err != nil {
		panic(err)
	}
	return
}

func MakeTestBlockHeader() bookkeeping.BlockHeader {
	// arbitrary genesis information
	genesisID := "simulation-test-v1"
	genesisHash, err := crypto.DigestFromString("3QF7SU53VLAQV6YIWENHUVANS4OFG5PHCTXPPX4EH7FEI3WIMJOQ")
	if err != nil {
		panic(err)
	}

	feeSink, rewardsPool := MakeSpecialAccounts()

	// convert test balances to AccountData balances
	testBalances := MakeTestBalances()
	acctDataBalances := make(map[basics.Address]basics.AccountData)
	for addr, balance := range testBalances {
		acctDataBalances[addr] = basics.AccountData{
			MicroAlgos: basics.MicroAlgos{Raw: balance},
		}
	}

	genesisBalances := bookkeeping.MakeGenesisBalances(acctDataBalances, feeSink, rewardsPool)
	genesisBlock, err := bookkeeping.MakeGenesisBlock(protocol.ConsensusCurrentVersion, genesisBalances, genesisID, genesisHash)
	if err != nil {
		panic(err)
	}

	return genesisBlock.BlockHeader
}

type account struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	Address    basics.Address
}

func AccountFromMnemonic(mnemonic string) (account, error) {
	key, err := passphrase.MnemonicToKey(mnemonic)
	if err != nil {
		return account{}, err
	}

	decoded := ed25519.NewKeyFromSeed(key)

	pk := decoded.Public().(ed25519.PublicKey)
	sk := decoded

	// Convert the public key to an address
	var addr basics.Address
	n := copy(addr[:], pk)
	if n != ed25519.PublicKeySize {
		return account{}, errors.New("generated public key is the wrong size")
	}

	return account{
		PublicKey:  pk,
		PrivateKey: sk,
		Address:    addr,
	}, nil
}

func SignatureSecretsFromAccount(acc account) (*crypto.SignatureSecrets, error) {
	var sk crypto.PrivateKey
	copy(sk[:], acc.PrivateKey)
	return crypto.SecretKeyToSignatureSecrets(sk)
}

func MakeTestAccounts() []account {
	// funded
	account1, err := AccountFromMnemonic("enforce voyage media inform embody borrow truck flat brave goose edit glide poet describe oxygen teach home choice motion engine wolf iron bachelor ability view")
	if err != nil {
		panic(err)
	}

	// unfunded
	account2, err := AccountFromMnemonic("husband around three crystal canvas arrive beach dumb pill sock inflict drink salmon modify gas monkey jungle chronic senior flavor ability witness resist abandon just")
	if err != nil {
		panic(err)
	}

	return []account{account1, account2}
}

func MakeTestBalances() map[basics.Address]uint64 {
	accounts := MakeTestAccounts()

	return map[basics.Address]uint64{
		accounts[0].Address: 1000000000,
	}
}

func MakeSimulationTestLedger() *SimulationTestLedger {
	hdr := MakeTestBlockHeader()
	balances := MakeTestBalances()
	balances[hdr.RewardsPool] = 1000000 // pool is always 1000000
	round := uint64(1)
	logicLedger := MakeLedgerForRound(balances, round)
	hdr.Round = basics.Round(round)
	l := SimulationTestLedger{logicLedger, hdr}
	return &l
}

func MakeBasicTxnHeader(sender basics.Address) transactions.Header {
	hdr := MakeTestBlockHeader()

	return transactions.Header{
		Fee:         basics.MicroAlgos{Raw: 1000},
		FirstValid:  basics.Round(1),
		GenesisID:   hdr.GenesisID,
		GenesisHash: hdr.GenesisHash,
		LastValid:   basics.Round(1001),
		Note:        []byte{240, 134, 38, 55, 197, 14, 142, 132},
		Sender:      sender,
	}
}

// Attach group ID to a transaction group. Mutates the group directly.
func AttachGroupID(txgroup []transactions.SignedTxn) error {
	txnArray := make([]transactions.Transaction, len(txgroup))
	for i, txn := range txgroup {
		txnArray[i] = txn.Txn
	}

	client := MakeTestClient()
	groupID, err := client.GroupID(txnArray)
	if err != nil {
		return err
	}

	for i := range txgroup {
		txgroup[i].Txn.Header.Group = groupID
	}

	return nil
}

// ==============================
// > Simulation Tests
// ==============================

func TestPayTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := MakeSimulationTestLedger()
	s := v2.MakeSimulator(l)

	accounts := MakeTestAccounts()
	sender := accounts[0].Address

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: MakeBasicTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	result, err := s.SimulateSignedTxGroup(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
}

func TestOverspendPayTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := MakeSimulationTestLedger()
	s := v2.MakeSimulator(l)

	accounts := MakeTestAccounts()
	sender := accounts[0].Address
	balances := MakeTestBalances()

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: MakeBasicTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: balances[sender] + 100}, // overspend
				},
			},
		},
	}

	result, err := s.SimulateSignedTxGroup(txgroup)
	require.NoError(t, err)
	require.Contains(t, *result.FailureMessage, "tried to spend {1000000100}")
}

func TestSimpleGroupTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := MakeSimulationTestLedger()
	s := v2.MakeSimulator(l)

	accounts := MakeTestAccounts()
	sender1 := accounts[0].Address
	sender2 := accounts[1].Address

	// Send money back and forth
	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: MakeBasicTxnHeader(sender1),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender2,
					Amount:   basics.MicroAlgos{Raw: 1000000},
				},
			},
		},
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: MakeBasicTxnHeader(sender2),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender1,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	// Should fail if there is no group parameter
	result, err := s.SimulateSignedTxGroup(txgroup)
	require.NoError(t, err)
	require.Contains(t, *result.FailureMessage, "had zero Group but was submitted in a group of 2")

	// Add group parameter
	AttachGroupID(txgroup)

	// Check balances before transaction
	sender1Data, _, err := l.LookupWithoutRewards(l.Latest(), sender1)
	require.NoError(t, err)
	require.Equal(t, basics.MicroAlgos{Raw: 1000000000}, sender1Data.MicroAlgos)

	sender2Data, _, err := l.LookupWithoutRewards(l.Latest(), sender2)
	require.NoError(t, err)
	require.Equal(t, basics.MicroAlgos{Raw: 0}, sender2Data.MicroAlgos)

	// Should now pass
	result, err = s.SimulateSignedTxGroup(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)

	// Confirm balances have not changed
	sender1Data, _, err = l.LookupWithoutRewards(l.Latest(), sender1)
	require.NoError(t, err)
	require.Equal(t, basics.MicroAlgos{Raw: 1000000000}, sender1Data.MicroAlgos)

	sender2Data, _, err = l.LookupWithoutRewards(l.Latest(), sender2)
	require.NoError(t, err)
	require.Equal(t, basics.MicroAlgos{Raw: 0}, sender2Data.MicroAlgos)
}

const trivialAVMProgram = `#pragma version 2
int 1`

func TestSimpleAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := MakeSimulationTestLedger()
	s := v2.MakeSimulator(l)

	accounts := MakeTestAccounts()
	sender := accounts[0].Address

	// Compile AVM program
	ops, err := AssembleString(trivialAVMProgram)
	require.NoError(t, err, ops.Errors)
	prog := ops.Program

	// Create program and call it
	futureAppID := 1
	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: MakeBasicTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:     0,
					ApprovalProgram:   prog,
					ClearStateProgram: prog,
					LocalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
					GlobalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
				},
			},
		},
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: MakeBasicTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:     basics.AppIndex(futureAppID),
					ApprovalProgram:   prog,
					ClearStateProgram: prog,
				},
			},
		},
	}

	AttachGroupID(txgroup)
	result, err := s.SimulateSignedTxGroup(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
}

func TestSignatureCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := MakeSimulationTestLedger()
	s := v2.MakeSimulator(l)

	accounts := MakeTestAccounts()
	sender := accounts[0].Address

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: MakeBasicTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	// should error without a signature
	result, err := s.SimulateSignedTxGroup(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
	require.Contains(t, *result.SignatureFailureMessage, "signedtxn has no sig")

	// add signature
	signatureSecrets, err := SignatureSecretsFromAccount(accounts[0])
	require.NoError(t, err)
	txgroup[0] = txgroup[0].Txn.Sign(signatureSecrets)

	// should not error now that we have a signature
	result, err = s.SimulateSignedTxGroup(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
	require.Empty(t, result.SignatureFailureMessage)
}
