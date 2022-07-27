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
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	. "github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
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

func MakeTestBlockHeader() bookkeeping.BlockHeader {
	genesisHash, err := crypto.DigestFromString("3QF7SU53VLAQV6YIWENHUVANS4OFG5PHCTXPPX4EH7FEI3WIMJOQ")
	if err != nil {
		panic(err)
	}

	// timestamp := time.Now().Unix()

	hdr := bookkeeping.BlockHeader{
		GenesisID:   "private-v1",
		GenesisHash: genesisHash,
		TimeStamp:   0,
	}
	hdr.CurrentProtocol = protocol.ConsensusCurrentVersion

	// TODO: These should be set in a more standard way.
	// Answer: Use genesis.go > MakeGenesisBlock()
	curRewardsState := bookkeeping.RewardsState{
		RewardsLevel:              0,
		RewardsRate:               11,
		RewardsResidue:            3,
		RewardsRecalculationRound: 110,
	}
	hdr.RewardsState = curRewardsState

	return hdr
}

func MakeTestAccounts() []basics.Address {
	account1, err := basics.UnmarshalChecksumAddress("DYFRROWPOCWPJ544DEUV7WMXIBRIDDXR4QMBLR2S2IHRL3OXQB6YLEGNRU")
	if err != nil {
		panic(err)
	}

	return []basics.Address{account1}
}

func MakeTestBalances() map[basics.Address]uint64 {
	accounts := MakeTestAccounts()

	return map[basics.Address]uint64{
		accounts[0]: 1000000000,
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

// ==============================
// > Simulation Tests
// ==============================

func TestPayTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := MakeSimulationTestLedger()
	s := v2.MakeSimulator(l)

	accounts := MakeTestAccounts()
	sender := accounts[0]

	hdr := MakeTestBlockHeader()

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Fee:         basics.MicroAlgos{Raw: 1000},
					FirstValid:  basics.Round(1),
					GenesisID:   hdr.GenesisID,
					GenesisHash: hdr.GenesisHash,
					LastValid:   basics.Round(1001),
					Note:        []byte{240, 134, 38, 55, 197, 14, 142, 132},
					Sender:      sender,
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	result, err := s.SimulateSignedTxGroup(txgroup)
	require.NoError(t, err)
	require.Empty(t, *result.FailureMessage)
}

func TestOverspendPayTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := MakeSimulationTestLedger()
	s := v2.MakeSimulator(l)

	accounts := MakeTestAccounts()
	sender := accounts[0]
	balances := MakeTestBalances()

	hdr := MakeTestBlockHeader()

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Fee:         basics.MicroAlgos{Raw: 1000},
					FirstValid:  basics.Round(1),
					GenesisID:   hdr.GenesisID,
					GenesisHash: hdr.GenesisHash,
					LastValid:   basics.Round(1001),
					Note:        []byte{240, 134, 38, 55, 197, 14, 142, 132},
					Sender:      sender,
				},
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
