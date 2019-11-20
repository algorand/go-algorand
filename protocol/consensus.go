// Copyright (C) 2019 Algorand, Inc.
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

package protocol

import (
	"fmt"
)

// ConsensusVersion is a string that identifies a version of the
// consensus protocol.
type ConsensusVersion string

// DEPRECATEDConsensusV0 is a baseline version of the Algorand consensus protocol.
// at the time versioning was introduced.
// It is now deprecated.
const DEPRECATEDConsensusV0 = ConsensusVersion("v0")

// DEPRECATEDConsensusV1 adds support for Genesis ID in transactions, but does not
// require it (transactions missing a GenesisID value are still allowed).
// It is now deprecated.
const DEPRECATEDConsensusV1 = ConsensusVersion("v1")

// DEPRECATEDConsensusV2 fixes a bug in the agreement protocol where proposalValues
// fail to commit to the original period and sender of a block.
const DEPRECATEDConsensusV2 = ConsensusVersion("v2")

// DEPRECATEDConsensusV3 adds support for fine-grained ephemeral keys.
const DEPRECATEDConsensusV3 = ConsensusVersion("v3")

// DEPRECATEDConsensusV4 adds support for a min balance and a transaction that
// closes out an account.
const DEPRECATEDConsensusV4 = ConsensusVersion("v4")

// DEPRECATEDConsensusV5 sets MinTxnFee to 1000 and fixes a blance lookback bug
const DEPRECATEDConsensusV5 = ConsensusVersion("v5")

// DEPRECATEDConsensusV6 adds support for explicit ephemeral-key parameters
const DEPRECATEDConsensusV6 = ConsensusVersion("v6")

// ConsensusV7 increases MaxBalLookback to 320 in preparation for
// the twin seeds change.
const ConsensusV7 = ConsensusVersion("v7")

// ConsensusV8 uses the new parameters and seed derivation policy
// from the agreement protocol's security analysis.
const ConsensusV8 = ConsensusVersion("v8")

// ConsensusV9 increases min balance to 100,000 microAlgos.
const ConsensusV9 = ConsensusVersion("v9")

// ConsensusV10 introduces fast partition recovery.
const ConsensusV10 = ConsensusVersion("v10")

// ConsensusV11 introduces efficient encoding of SignedTxn using SignedTxnInBlock.
const ConsensusV11 = ConsensusVersion("v11")

// ConsensusV12 increases the maximum length of a version string.
const ConsensusV12 = ConsensusVersion("v12")

// ConsensusV13 makes the consensus version a meaningful string.
const ConsensusV13 = ConsensusVersion(
	// Points to version of the Algorand spec as of May 21, 2019.
	"https://github.com/algorand/spec/tree/0c8a9dc44d7368cc266d5407b79fb3311f4fc795",
)

// ConsensusV14 adds tracking of closing amounts in ApplyData,
// and enables genesis hash in transactions.
const ConsensusV14 = ConsensusVersion(
	"https://github.com/algorand/spec/tree/2526b6ae062b4fe5e163e06e41e1d9b9219135a9",
)

// ConsensusV15 adds tracking of reward distributions in ApplyData.
const ConsensusV15 = ConsensusVersion(
	"https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622",
)

// ConsensusV16 fixes domain separation in Credentials and requires GenesisHash.
const ConsensusV16 = ConsensusVersion(
	"https://github.com/algorand/spec/tree/22726c9dcd12d9cddce4a8bd7e8ccaa707f74101",
)

// ConsensusV17 points to 'final' spec commit for 2019 june release
const ConsensusV17 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/5615adc36bad610c7f165fa2967f4ecfa75125f0",
)

// ConsensusV18 points to reward calculation spec commit
const ConsensusV18 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/6c6bd668be0ab14098e51b37e806c509f7b7e31f",
)

// ConsensusV19 points to 'final' spec commit for 2019 nov release
const ConsensusV19 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/0e196e82bfd6e327994bec373c4cc81bc878ef5c",
)

// ConsensusFuture is a protocol that should not appear in any production
// network, but is used to test features before they are released.
const ConsensusFuture = ConsensusVersion(
	"future",
)

// !!! ********************* !!!
// !!! *** Please update ConsensusCurrentVersion when adding new protocol versions *** !!!
// !!! ********************* !!!

// ConsensusCurrentVersion is the latest version and should be used
// when a specific version is not provided.
const ConsensusCurrentVersion = ConsensusV19

// ConsensusTest0 is a version of ConsensusV0 used for testing
// (it has different approved upgrade paths).
const ConsensusTest0 = ConsensusVersion("test0")

// ConsensusTest1 is an extension of ConsensusTest0 that
// supports a sorted-list balance commitment.
const ConsensusTest1 = ConsensusVersion("test1")

// ConsensusTestBigBlocks is a version of ConsensusV0 used for testing
// with big block size (large MaxTxnBytesPerBlock).
// at the time versioning was introduced.
const ConsensusTestBigBlocks = ConsensusVersion("test-big-blocks")

// ConsensusTestRapidRewardRecalculation is a version of ConsensusCurrentVersion
// that decreases the RewardRecalculationInterval greatly.
const ConsensusTestRapidRewardRecalculation = ConsensusVersion("test-fast-reward-recalculation")

// ConsensusTestShorterLookback is a version of ConsensusCurrentVersion
// that decreases the MaxBalLookback greatly.
const ConsensusTestShorterLookback = ConsensusVersion("test-shorter-lookback")

// ConsensusTestFastUpgrade is meant for testing of protocol upgrades:
// during testing, it is equivalent to another protocol with the exception
// of the upgrade parameters, which allow for upgrades to take place after
// only a few rounds.
func ConsensusTestFastUpgrade(proto ConsensusVersion) ConsensusVersion {
	return "test-fast-upgrade-" + proto
}

// Error is used to indicate that an unsupported protocol has been detected.
type Error ConsensusVersion

// Error satisfies builtin interface `error`
func (err Error) Error() string {
	proto := ConsensusVersion(err)
	return fmt.Sprintf("protocol not supported: %s", proto)
}
