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

package verify

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func invokeValidateStateProof(latestRoundInIntervalHdr *bookkeeping.BlockHeader,
	stateProof *stateproof.StateProof,
	votersHdr *bookkeeping.BlockHeader,
	atRound basics.Round,
	msg *stateproofmsg.Message) error {
	verificationContext := ledgercore.StateProofVerificationContext{
		LastAttestedRound: latestRoundInIntervalHdr.Round,
		VotersCommitment:  votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		OnlineTotalWeight: votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		Version:           votersHdr.CurrentProtocol,
	}
	return ValidateStateProof(&verificationContext, stateProof, atRound, msg)
}

func TestValidateStateProof(t *testing.T) {
	partitiontest.PartitionTest(t)

	spHdr := &bookkeeping.BlockHeader{}
	sp := &stateproof.StateProof{}
	votersHdr := &bookkeeping.BlockHeader{}
	var atRound basics.Round
	msg := &stateproofmsg.Message{BlockHeadersCommitment: []byte("this is an arbitrary message")}

	// will definitely fail with nothing set up
	err := invokeValidateStateProof(spHdr, sp, votersHdr, atRound, msg)
	require.ErrorIs(t, err, errStateProofNotEnabled)

	votersHdr.CurrentProtocol = "TestValidateStateProof"
	proto := config.Consensus[spHdr.CurrentProtocol]
	proto.StateProofInterval = 256
	proto.StateProofStrengthTarget = 256
	proto.StateProofWeightThreshold = (1 << 32) * 30 / 100
	config.Consensus[votersHdr.CurrentProtocol] = proto

	spHdr.Round = 1
	err = invokeValidateStateProof(spHdr, sp, votersHdr, atRound, msg)
	require.ErrorIs(t, err, errNotAtRightMultiple)

	votersHdr.Round = 256
	spHdr.Round = votersHdr.Round + basics.Round(proto.StateProofInterval)
	sp.SignedWeight = 1
	atRound = 800
	err = invokeValidateStateProof(spHdr, sp, votersHdr, atRound, msg)
	require.ErrorIs(t, err, stateproof.ErrIllegalInputForLnApprox)

	votersHdr.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	cc := votersHdr.StateProofTracking[protocol.StateProofBasic]
	cc.StateProofOnlineTotalWeight.Raw = 100
	votersHdr.StateProofTracking[protocol.StateProofBasic] = cc
	// Require 100% of the weight to be signed in order to accept stateproof before interval/2 rounds has passed from the latest round attested (optimal case)
	sp.SignedWeight = 99 // suboptimal signed weight
	atRound = votersHdr.Round + basics.Round(proto.StateProofInterval)
	err = invokeValidateStateProof(spHdr, sp, votersHdr, atRound, msg)
	require.ErrorIs(t, err, errInsufficientWeight)

	atRound++
	err = invokeValidateStateProof(spHdr, sp, votersHdr, atRound, msg)
	require.ErrorIs(t, err, errInsufficientWeight)

	// we don't pass the scaled weight
	sp.SignedWeight = 96
	latestRoundInProof := votersHdr.Round + basics.Round(proto.StateProofInterval)
	atRound = latestRoundInProof + basics.Round(proto.StateProofInterval/2) + 5
	err = invokeValidateStateProof(spHdr, sp, votersHdr, atRound, msg)
	require.ErrorIs(t, err, errInsufficientWeight)

	// we will pass the threshold since the network is now willing to take any state proof that has signedWeight over the threshold
	sp.SignedWeight = 30
	atRound = votersHdr.Round + 2*basics.Round(proto.StateProofInterval)
	err = invokeValidateStateProof(spHdr, sp, votersHdr, atRound, msg)
	require.ErrorIs(t, err, errStateProofCrypto)

	// Above cases leave validateStateProof() with 100% coverage.
	// crypto/stateproof.Verify has its own tests
}

func TestAcceptableStateProofWeight(t *testing.T) {
	partitiontest.PartitionTest(t)

	var votersHdr bookkeeping.BlockHeader
	var firstValid basics.Round
	logger := logging.TestingLog(t)

	votersHdr.CurrentProtocol = "TestAcceptableStateProofWeight"
	proto := config.Consensus[votersHdr.CurrentProtocol]
	proto.StateProofInterval = 2
	config.Consensus[votersHdr.CurrentProtocol] = proto
	out := AcceptableStateProofWeight(&votersHdr, firstValid, logger)
	require.Equal(t, uint64(0), out)

	votersHdr.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	cc := votersHdr.StateProofTracking[protocol.StateProofBasic]
	cc.StateProofOnlineTotalWeight.Raw = 100
	votersHdr.StateProofTracking[protocol.StateProofBasic] = cc
	out = AcceptableStateProofWeight(&votersHdr, firstValid, logger)
	require.Equal(t, uint64(100), out)

	// this should exercise the second return case
	firstValid = basics.Round(3)
	out = AcceptableStateProofWeight(&votersHdr, firstValid, logger)
	require.Equal(t, uint64(100), out)

	firstValid = basics.Round(6)
	proto.StateProofWeightThreshold = 999999999
	config.Consensus[votersHdr.CurrentProtocol] = proto
	out = AcceptableStateProofWeight(&votersHdr, firstValid, logger)
	require.Equal(t, uint64(0x17), out)

	proto.StateProofInterval = 10000
	votersHdr.Round = 10000
	firstValid = basics.Round(29000 - 2)
	config.Consensus[votersHdr.CurrentProtocol] = proto
	cc.StateProofOnlineTotalWeight.Raw = 0x7fffffffffffffff
	votersHdr.StateProofTracking[protocol.StateProofBasic] = cc
	proto.StateProofWeightThreshold = 0x7fffffff
	config.Consensus[votersHdr.CurrentProtocol] = proto
	out = AcceptableStateProofWeight(&votersHdr, firstValid, logger)
	require.Equal(t, uint64(0x4cd35a85213a92a2), out)

	// Covers everything except "overflow that shouldn't happen" branches
}

func TestStateProofParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	var votersHdr bookkeeping.BlockHeader
	var hdr bookkeeping.BlockHeader

	_, err := GetProvenWeight(&votersHdr, &hdr)
	require.Error(t, err) // not enabled

	votersHdr.CurrentProtocol = "TestStateProofParams"
	proto := config.Consensus[votersHdr.CurrentProtocol]
	proto.StateProofInterval = 2
	config.Consensus[votersHdr.CurrentProtocol] = proto
	votersHdr.Round = 1
	_, err = GetProvenWeight(&votersHdr, &hdr)
	require.Error(t, err) // wrong round

	votersHdr.Round = 2
	hdr.Round = 3
	_, err = GetProvenWeight(&votersHdr, &hdr)
	require.Error(t, err) // wrong round

	// Covers all cases except overflow
}
