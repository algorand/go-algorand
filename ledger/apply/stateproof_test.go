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

package apply

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type stateProofApplierMock struct {
	spNext                 basics.Round
	blocks                 map[basics.Round]bookkeeping.BlockHeader
	blockErr               map[basics.Round]error
	stateProofVerification map[basics.Round]*ledgercore.StateProofVerificationContext
}

func (s *stateProofApplierMock) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	err, hit := s.blockErr[rnd]
	if hit {
		return bookkeeping.BlockHeader{}, err
	}
	hdr := s.blocks[rnd] // default struct is fine if nothing found
	return hdr, nil
}

func (s *stateProofApplierMock) GetStateProofNextRound() basics.Round {
	return s.spNext
}

func (s *stateProofApplierMock) SetStateProofNextRound(rnd basics.Round) {
	s.spNext = rnd
}

func (s *stateProofApplierMock) StateProofVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	element, exists := s.stateProofVerification[stateProofLastAttestedRound]
	if !exists {
		return nil, fmt.Errorf("requested state proof verification data not found")
	}
	return element, nil
}

func TestCowStateProofV34(t *testing.T) {
	partitiontest.PartitionTest(t)

	var spType protocol.StateProofType
	var stateProof stateproof.StateProof
	var atRound basics.Round
	var validate bool
	msg := stateproofmsg.Message{}

	const version = protocol.ConsensusV34

	blocks := make(map[basics.Round]bookkeeping.BlockHeader)
	blockErr := make(map[basics.Round]error)
	mockApplier := &stateProofApplierMock{
		spNext:                 0,
		blocks:                 blocks,
		blockErr:               blockErr,
		stateProofVerification: nil,
	}

	spType = protocol.StateProofType(1234) // bad stateproof type
	stateProofTx := transactions.StateProofTxnFields{
		StateProofType: spType,
		StateProof:     stateProof,
		Message:        msg,
	}
	err := StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, ErrStateProofTypeNotSupported)

	stateProofTx.StateProofType = protocol.StateProofBasic
	// stateproof txn doesn't confirm the next state proof round. expected is in the past
	validate = true
	stateProofTx.Message.LastAttestedRound = uint64(16)
	mockApplier.SetStateProofNextRound(8)
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, ErrExpectedDifferentStateProofRound)
	mockApplier.SetStateProofNextRound(32)

	// stateproof txn doesn't confirm the next state proof round. expected is in the future
	validate = true
	stateProofTx.Message.LastAttestedRound = uint64(16)
	mockApplier.SetStateProofNextRound(32)
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, ErrExpectedDifferentStateProofRound)

	// no atRound block
	noBlockErr := errors.New("no block")
	blockErr[atRound] = noBlockErr
	stateProofTx.Message.LastAttestedRound = 32
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, noBlockErr)
	delete(blockErr, atRound)

	atRoundBlock := bookkeeping.BlockHeader{}
	atRoundBlock.CurrentProtocol = version
	blocks[atRound] = atRoundBlock

	// no spRnd block
	noBlockErr = errors.New("no block")
	blockErr[32] = noBlockErr
	stateProofTx.Message.LastAttestedRound = 32
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, noBlockErr)

	// no votersRnd block
	// this is slightly a mess of things that don't quite line up with likely usage
	validate = true
	var spHdr bookkeeping.BlockHeader
	spHdr.CurrentProtocol = "TestCowStateProof"
	spHdr.Round = 1
	proto := config.Consensus[spHdr.CurrentProtocol]
	proto.StateProofInterval = 2
	config.Consensus[spHdr.CurrentProtocol] = proto
	blocks[spHdr.Round] = spHdr

	spHdr.Round = 15
	blocks[spHdr.Round] = spHdr
	stateProofTx.Message.LastAttestedRound = uint64(spHdr.Round)
	mockApplier.SetStateProofNextRound(15)
	blockErr[13] = noBlockErr
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.Contains(t, err.Error(), "no block")
	delete(blockErr, 13)

	// check the happy flow - we should fail only on crypto
	atRound = 800
	spHdr = bookkeeping.BlockHeader{}
	spHdr.CurrentProtocol = version
	blocks[basics.Round(2*config.Consensus[version].StateProofInterval)] = spHdr

	votersHdr := bookkeeping.BlockHeader{}
	votersHdr.CurrentProtocol = version
	stateproofTracking := bookkeeping.StateProofTrackingData{
		StateProofVotersCommitment:  []byte{0x1}[:],
		StateProofOnlineTotalWeight: basics.MicroAlgos{Raw: 5},
	}
	votersHdr.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	votersHdr.StateProofTracking[protocol.StateProofBasic] = stateproofTracking

	blocks[basics.Round(config.Consensus[version].StateProofInterval)] = votersHdr
	atRoundBlock = bookkeeping.BlockHeader{}
	atRoundBlock.CurrentProtocol = version
	blocks[atRound] = atRoundBlock

	stateProofTx.Message.LastAttestedRound = 2 * config.Consensus[version].StateProofInterval
	stateProofTx.StateProof.SignedWeight = 100
	mockApplier.SetStateProofNextRound(basics.Round(2 * config.Consensus[version].StateProofInterval))

	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.Contains(t, err.Error(), "crypto error")
}

func TestCowStateProof(t *testing.T) {
	partitiontest.PartitionTest(t)

	var spType protocol.StateProofType
	var stateProof stateproof.StateProof
	atRound := basics.Round(600)
	var validate bool
	msg := stateproofmsg.Message{}

	blocks := make(map[basics.Round]bookkeeping.BlockHeader)
	blockErr := make(map[basics.Round]error)
	spVerification := make(map[basics.Round]*ledgercore.StateProofVerificationContext)

	mockApplier := &stateProofApplierMock{
		spNext:                 0,
		blocks:                 blocks,
		blockErr:               blockErr,
		stateProofVerification: spVerification,
	}

	spType = protocol.StateProofType(1234) // bad stateproof type
	stateProofTx := transactions.StateProofTxnFields{
		StateProofType: spType,
		StateProof:     stateProof,
		Message:        msg,
	}
	err := StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, ErrStateProofTypeNotSupported)

	stateProofTx.StateProofType = protocol.StateProofBasic
	// stateproof txn doesn't confirm the next state proof round. expected is in the past
	validate = true
	stateProofTx.Message.LastAttestedRound = uint64(16)
	mockApplier.SetStateProofNextRound(8)
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, ErrExpectedDifferentStateProofRound)
	mockApplier.SetStateProofNextRound(32)

	// stateproof txn doesn't confirm the next state proof round. expected is in the future
	validate = true
	stateProofTx.Message.LastAttestedRound = uint64(16)
	mockApplier.SetStateProofNextRound(32)
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, ErrExpectedDifferentStateProofRound)

	atRoundBlock := bookkeeping.BlockHeader{}
	atRoundBlock.CurrentProtocol = protocol.ConsensusFuture
	blocks[atRound] = atRoundBlock

	validate = true
	// no atRound block
	noBlockErr := errors.New("no block")
	blockErr[atRound] = noBlockErr
	stateProofTx.Message.LastAttestedRound = 32
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, noBlockErr)
	delete(blockErr, atRound)

	noBlockErr = errors.New("no block")

	// removing blocks for the ledger so if apply.stateproof uses the tracker it should pass
	mockApplier.SetStateProofNextRound(512)
	blockErr[512] = noBlockErr
	blockErr[256] = noBlockErr
	stateProofTx.Message.LastAttestedRound = 512
	stateProofTx.StateProof.SignedWeight = 100
	mockApplier.stateProofVerification[basics.Round(stateProofTx.Message.LastAttestedRound)] = &ledgercore.StateProofVerificationContext{
		LastAttestedRound: basics.Round(stateProofTx.Message.LastAttestedRound),
		VotersCommitment:  []byte{0x1}[:],
		OnlineTotalWeight: basics.MicroAlgos{Raw: 5},
		Version:           protocol.ConsensusFuture,
	}

	// if atRound header is missing the apply should fail
	blockErr[atRound] = noBlockErr
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.ErrorIs(t, err, noBlockErr)

	delete(blockErr, atRound)
	err = StateProof(stateProofTx, atRound, mockApplier, validate)
	require.Error(t, err)
	require.Contains(t, err.Error(), "crypto error")
}
