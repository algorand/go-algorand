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

package apply

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type mockStateProof struct {
	stateProofRound basics.Round
	blockHeaders    map[basics.Round]bookkeeping.BlockHeader
}

func makeMockStateProof(stateProofBlockHeader bookkeeping.BlockHeader, votersHeader bookkeeping.BlockHeader) mockStateProof {
	mock := mockStateProof{}
	mock.blockHeaders = make(map[basics.Round]bookkeeping.BlockHeader, 2)
	mock.blockHeaders[stateProofBlockHeader.Round] = stateProofBlockHeader
	mock.blockHeaders[votersHeader.Round] = votersHeader
	mock.stateProofRound = 512

	return mock
}

func (m *mockStateProof) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	if element, ok := m.blockHeaders[r]; ok {
		return element, nil
	}
	return bookkeeping.BlockHeader{}, errors.New("blockheader can not be found")
}

func (m *mockStateProof) GetStateProofNextRound() basics.Round {
	return m.stateProofRound
}
func (m *mockStateProof) SetStateProofNextRound(rnd basics.Round) {
	m.stateProofRound = rnd
}

func TestValidateStateProof(t *testing.T) {
	partitiontest.PartitionTest(t)

	const testVersion = "testVersion"
	proto := config.Consensus[protocol.ConsensusFuture]
	proto.StateProofInterval = 256
	proto.StateProofStrengthTarget = 256
	proto.StateProofWeightThreshold = (1 << 32) * 30 / 100
	config.Consensus["testVersion"] = proto

	stateProofBlockHeader := bookkeeping.BlockHeader{}
	stateProofBlockHeader.Round = 512
	stateProofBlockHeader.CurrentProtocol = testVersion
	votersBlockHeader := bookkeeping.BlockHeader{}
	votersBlockHeader.Round = 256
	tracking := bookkeeping.StateProofTrackingData{StateProofVotersTotalWeight: basics.MicroAlgos{Raw: 3000}}
	votersBlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	votersBlockHeader.StateProofTracking[protocol.StateProofBasic] = tracking
	votersBlockHeader.CurrentProtocol = testVersion

	stateProofValidator := makeMockStateProof(stateProofBlockHeader, votersBlockHeader)

	stateProofTxn := transactions.StateProofTxnFields{}
	stateProofTxn.StateProofIntervalLastRound = 512
	stateProofTxn.StateProof.SignedWeight = 3000

	atRound := basics.Round(770)

	err := StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.NoError(t, err)
	require.Equal(t, stateProofValidator.stateProofRound, basics.Round(768))
	stateProofValidator.stateProofRound = 512

	stateProofTxn.StateProofType = 1
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errStateProofTypeNotSupported)

	stateProofTxn.StateProofType = 0

	proto = config.Consensus[protocol.ConsensusFuture]
	proto.StateProofInterval = 0
	config.Consensus["testVersion"] = proto

	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errStateProofNotEnabled)

	proto = config.Consensus[protocol.ConsensusFuture]
	proto.StateProofInterval = 256
	config.Consensus["testVersion"] = proto

	stateProofTxn.StateProofIntervalLastRound = 255
	bk := bookkeeping.BlockHeader{}
	bk.CurrentProtocol = testVersion
	bk.Round = 255
	stateProofValidator.blockHeaders[255] = bk

	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errExpectedDifferentStateProofRound)

	stateProofTxn.StateProofIntervalLastRound = 1280
	bk = bookkeeping.BlockHeader{}
	bk.CurrentProtocol = testVersion
	bk.Round = 1280
	stateProofValidator.blockHeaders[1280] = bk

	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errExpectedDifferentStateProofRound)

	stateProofTxn.StateProofIntervalLastRound = 255
	bk = bookkeeping.BlockHeader{}
	bk.CurrentProtocol = testVersion
	bk.Round = 255
	stateProofValidator.blockHeaders[255] = bk
	stateProofValidator.stateProofRound = 255

	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errNotAtRightMultiple)

	stateProofValidator.stateProofRound = 512
	stateProofTxn.StateProofIntervalLastRound = 512

	// the first round is even before the state proof round -> we need 100% of the stake
	stateProofTxn.StateProof.SignedWeight = 3000 - 1
	atRound = 100
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errInsufficientWeight)
	stateProofTxn.StateProof.SignedWeight = 3000
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.NoError(t, err)
	stateProofValidator.stateProofRound = 512

	// the first round is before the interval/2 -> we need 100% of the stake
	stateProofTxn.StateProof.SignedWeight = 3000 - 1
	atRound = 640
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errInsufficientWeight)
	stateProofTxn.StateProof.SignedWeight = 3000
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.NoError(t, err)
	stateProofValidator.stateProofRound = 512

	// the first round is after the interval/2 -> we need 100% of the stake
	stateProofTxn.StateProof.SignedWeight = 898 // 999???
	atRound = 768
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errInsufficientWeight)
	stateProofTxn.StateProof.SignedWeight = 899
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.NoError(t, err)
	stateProofValidator.stateProofRound = 512

	// the first round is within [stateproofinterval/2 ,  stateproofinterval+1/2]
	stateProofTxn.StateProof.SignedWeight = 2014
	atRound = 700
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.ErrorIs(t, err, errInsufficientWeight)
	stateProofTxn.StateProof.SignedWeight = 2015
	err = StateProof(stateProofTxn, atRound, &stateProofValidator, true)
	require.NoError(t, err)
	stateProofValidator.stateProofRound = 512

}
