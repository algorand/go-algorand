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

package config

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestConsensusParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	for proto, params := range Consensus {
		// Our implementation of Payset.Commit() assumes that
		// SupportSignedTxnInBlock implies not PaysetCommitUnsupported.
		if params.SupportSignedTxnInBlock && params.PaysetCommit == PaysetCommitUnsupported {
			t.Errorf("Protocol %s: SupportSignedTxnInBlock with PaysetCommitUnsupported", proto)
		}

		// ApplyData requires not PaysetCommitUnsupported.
		if params.ApplyData && params.PaysetCommit == PaysetCommitUnsupported {
			t.Errorf("Protocol %s: ApplyData with PaysetCommitUnsupported", proto)
		}

		// To figure out challenges, nodes must be able to lookup headers up to two GracePeriods back
		if 2*params.Payouts.ChallengeGracePeriod > params.MaxTxnLife+params.DeeperBlockHeaderHistory {
			t.Errorf("Protocol %s: Grace period is too long", proto)
		}
	}
}

// TestConsensusUpgradeWindow ensures that the upgrade window is a non-zero value, and confirm to be within the valid range.
func TestConsensusUpgradeWindow(t *testing.T) {
	partitiontest.PartitionTest(t)

	for proto, params := range Consensus {
		require.GreaterOrEqualf(t, params.MaxUpgradeWaitRounds, params.MinUpgradeWaitRounds, "Version :%v", proto)
		for toVersion, delay := range params.ApprovedUpgrades {
			if params.MinUpgradeWaitRounds != 0 || params.MaxUpgradeWaitRounds != 0 {
				require.NotZerof(t, delay, "From :%v\nTo :%v", proto, toVersion)
				require.GreaterOrEqualf(t, delay, params.MinUpgradeWaitRounds, "From :%v\nTo :%v", proto, toVersion)
				require.LessOrEqualf(t, delay, params.MaxUpgradeWaitRounds, "From :%v\nTo :%v", proto, toVersion)
			} else {
				require.Zerof(t, delay, "From :%v\nTo :%v", proto, toVersion)

			}
		}
	}
}

func TestConsensusUpgradeWindow_NetworkOverrides(t *testing.T) {
	partitiontest.PartitionTest(t)

	ApplyShorterUpgradeRoundsForDevNetworks(Devnet)
	for _, params := range Consensus {
		for toVersion, delay := range params.ApprovedUpgrades {
			if params.MinUpgradeWaitRounds != 0 || params.MaxUpgradeWaitRounds != 0 {
				require.NotZerof(t, delay, "From :%v\nTo :%v", params, toVersion)
				require.Equalf(t, delay, params.MinUpgradeWaitRounds, "From :%v\nTo :%v", params, toVersion)
				// This check is not really needed, but leaving for sanity
				require.LessOrEqualf(t, delay, params.MaxUpgradeWaitRounds, "From :%v\nTo :%v", params, toVersion)
			} else {
				// If no MinUpgradeWaitRounds is set, leaving everything as zero value is expected
				require.Zerof(t, delay, "From :%v\nTo :%v", params, toVersion)
			}
		}
	}

	// Should be no-ops for Mainnet
	Consensus = make(ConsensusProtocols)
	initConsensusProtocols()

	origConsensus := Consensus.DeepCopy()
	ApplyShorterUpgradeRoundsForDevNetworks(Mainnet)
	require.EqualValues(t, origConsensus, Consensus)
	for _, params := range Consensus {
		for toVersion, delay := range params.ApprovedUpgrades {
			if params.MinUpgradeWaitRounds != 0 || params.MaxUpgradeWaitRounds != 0 {
				require.NotZerof(t, delay, "From :%v\nTo :%v", params, toVersion)
				require.GreaterOrEqualf(t, delay, params.MinUpgradeWaitRounds, "From :%v\nTo :%v", params, toVersion)
				require.LessOrEqualf(t, delay, params.MaxUpgradeWaitRounds, "From :%v\nTo :%v", params, toVersion)
			} else {
				require.Zerof(t, delay, "From :%v\nTo :%v", params, toVersion)

			}
		}
	}

	// reset consensus settings
	Consensus = make(ConsensusProtocols)
	initConsensusProtocols()

	ApplyShorterUpgradeRoundsForDevNetworks(Betanet)
	for _, params := range Consensus {
		for toVersion, delay := range params.ApprovedUpgrades {
			if params.MinUpgradeWaitRounds != 0 || params.MaxUpgradeWaitRounds != 0 {
				require.NotZerof(t, delay, "From :%v\nTo :%v", params, toVersion)
				require.Equalf(t, delay, params.MinUpgradeWaitRounds, "From :%v\nTo :%v", params, toVersion)
				// This check is not really needed, but leaving for sanity
				require.LessOrEqualf(t, delay, params.MaxUpgradeWaitRounds, "From :%v\nTo :%v", params, toVersion)
			} else {
				// If no MinUpgradeWaitRounds is set, leaving everything as zero value is expected
				require.Zerof(t, delay, "From :%v\nTo :%v", params, toVersion)
			}
		}
	}

	// should be no-ops for Testnet
	Consensus = make(ConsensusProtocols)
	initConsensusProtocols()

	ApplyShorterUpgradeRoundsForDevNetworks(Testnet)
	require.EqualValues(t, origConsensus, Consensus)
	for _, params := range Consensus {
		for toVersion, delay := range params.ApprovedUpgrades {
			if params.MinUpgradeWaitRounds != 0 || params.MaxUpgradeWaitRounds != 0 {
				require.NotZerof(t, delay, "From :%v\nTo :%v", params, toVersion)
				require.GreaterOrEqualf(t, delay, params.MinUpgradeWaitRounds, "From :%v\nTo :%v", params, toVersion)
				require.LessOrEqualf(t, delay, params.MaxUpgradeWaitRounds, "From :%v\nTo :%v", params, toVersion)
			} else {
				require.Zerof(t, delay, "From :%v\nTo :%v", params, toVersion)

			}
		}
	}
}

func TestConsensusStateProofParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, params := range Consensus {
		if params.StateProofInterval != 0 {
			require.Equal(t, uint64(1<<16), (params.MaxKeyregValidPeriod+1)/params.StateProofInterval,
				"Validity period divided by StateProofInterval should allow for no more than %d generated keys", 1<<16)
		}
	}
}
