// Copyright (C) 2019-2025 Algorand, Inc.
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

package test

import (
	"fmt"

	"github.com/stretchr/testify/mock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
)

var cannedStatusReportCaughtUpAndReadyGolden = node.StatusReport{
	LastRound:                          basics.Round(1),
	LastVersion:                        protocol.ConsensusCurrentVersion,
	NextVersion:                        protocol.ConsensusCurrentVersion,
	NextVersionRound:                   basics.Round(2),
	NextVersionSupported:               true,
	StoppedAtUnsupportedRound:          false,
	Catchpoint:                         "",
	CatchpointCatchupAcquiredBlocks:    0,
	CatchpointCatchupProcessedAccounts: 0,
	CatchpointCatchupVerifiedAccounts:  0,
	CatchpointCatchupTotalAccounts:     0,
	CatchpointCatchupTotalKVs:          0,
	CatchpointCatchupProcessedKVs:      0,
	CatchpointCatchupVerifiedKVs:       0,
	CatchpointCatchupTotalBlocks:       0,
	LastCatchpoint:                     "",
	CatchupTime:                        0,
}

var cannedStatusReportCatchingUpFastGolden = node.StatusReport{
	LastRound:                          basics.Round(97000),
	LastVersion:                        protocol.ConsensusCurrentVersion,
	NextVersion:                        protocol.ConsensusCurrentVersion,
	NextVersionRound:                   200000,
	NextVersionSupported:               true,
	StoppedAtUnsupportedRound:          false,
	Catchpoint:                         "5894690#DVFRZUYHEFKRLK5N6DNJRR4IABEVN2D6H76F3ZSEPIE6MKXMQWQA",
	CatchpointCatchupAcquiredBlocks:    0,
	CatchpointCatchupProcessedAccounts: 0,
	CatchpointCatchupVerifiedAccounts:  0,
	CatchpointCatchupTotalAccounts:     0,
	CatchpointCatchupTotalKVs:          0,
	CatchpointCatchupProcessedKVs:      0,
	CatchpointCatchupVerifiedKVs:       0,
	CatchpointCatchupTotalBlocks:       0,
	LastCatchpoint:                     "",
	UpgradePropose:                     "upgradePropose",
	UpgradeApprove:                     false,
	UpgradeDelay:                       0,
	NextProtocolVoteBefore:             100000,
	NextProtocolApprovals:              5000,
	CatchupTime:                        10000,
}

var cannedStatusReportStoppedAtUnsupportedGolden = node.StatusReport{
	LastRound:                          basics.Round(97000),
	LastVersion:                        protocol.ConsensusCurrentVersion,
	NextVersion:                        protocol.ConsensusCurrentVersion,
	NextVersionRound:                   200000,
	NextVersionSupported:               true,
	StoppedAtUnsupportedRound:          true,
	Catchpoint:                         "",
	CatchpointCatchupAcquiredBlocks:    0,
	CatchpointCatchupProcessedAccounts: 0,
	CatchpointCatchupVerifiedAccounts:  0,
	CatchpointCatchupTotalAccounts:     0,
	CatchpointCatchupTotalKVs:          0,
	CatchpointCatchupProcessedKVs:      0,
	CatchpointCatchupVerifiedKVs:       0,
	CatchpointCatchupTotalBlocks:       0,
	LastCatchpoint:                     "",
	UpgradePropose:                     "upgradePropose",
	UpgradeApprove:                     false,
	UpgradeDelay:                       0,
	NextProtocolVoteBefore:             100000,
	NextProtocolApprovals:              5000,
	CatchupTime:                        0,
}

// MockNodeCatchupStatus enumerates over possible mock status of a mock node in testing
type MockNodeCatchupStatus uint

const (
	// CaughtUpAndReady stands for testing mock node is finishing catching up, /ready should return 200
	CaughtUpAndReady = iota
	// CatchingUpFast stands for mock node is mocking fast catch up state, /ready should return 400
	CatchingUpFast
	// StoppedAtUnsupported stands for mock node stopped at unsupported round, /ready should return 500
	StoppedAtUnsupported
)

// mockNode is the "node" we use in common endpoint testing, implements NodeInterface
type mockNode struct {
	mock.Mock
	catchupStatus MockNodeCatchupStatus
}

// makeMockNode creates a mock common node for ready endpoint testing.
func makeMockNode(catchupStatus MockNodeCatchupStatus) *mockNode {
	return &mockNode{catchupStatus: catchupStatus}
}

func (m *mockNode) Status() (s node.StatusReport, err error) {
	switch m.catchupStatus {
	case CaughtUpAndReady:
		s = cannedStatusReportCaughtUpAndReadyGolden
	case CatchingUpFast:
		s = cannedStatusReportCatchingUpFastGolden
	case StoppedAtUnsupported:
		s = cannedStatusReportStoppedAtUnsupportedGolden
	default:
		err = fmt.Errorf("catchup status out of scope error")
	}
	return
}

func (m *mockNode) GenesisID() string { panic("not implemented") }

func (m *mockNode) GenesisHash() crypto.Digest { panic("not implemented") }

func (m *mockNode) GetPeers() (inboundPeers []network.Peer, outboundPeers []network.Peer, err error) {
	panic("not implemented")
}
