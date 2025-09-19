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

package protocol

import (
	"fmt"
)

// ConsensusVersion is a string that identifies a version of the
// consensus protocol.
//
//msgp:allocbound ConsensusVersion bounds.MaxConsensusVersionLen
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

// ConsensusV20 points to adding the decimals field to assets
const ConsensusV20 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/4a9db6a25595c6fd097cf9cc137cc83027787eaa",
)

// ConsensusV21 fixes a bug in credential.lowestOutput
const ConsensusV21 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/8096e2df2da75c3339986317f9abe69d4fa86b4b",
)

// ConsensusV22 allows tuning the upgrade delay.
const ConsensusV22 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/57016b942f6d97e6d4c0688b373bb0a2fc85a1a2",
)

// ConsensusV23 fixes lease behavior.
const ConsensusV23 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/e5f565421d720c6f75cdd186f7098495caf9101f",
)

// ConsensusV24 include the applications, rekeying and AVM v2
const ConsensusV24 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/3a83c4c743f8b17adfd73944b4319c25722a6782",
)

// ConsensusV25 adds support for AssetCloseAmount in the ApplyData
const ConsensusV25 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/bea19289bf41217d2c0af30522fa222ef1366466",
)

// ConsensusV26 adds support for TEAL 3, initial rewards calculation and merkle tree hash commitments
const ConsensusV26 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/ac2255d586c4474d4ebcf3809acccb59b7ef34ff",
)

// ConsensusV27 updates ApplyDelta.EvalDelta.LocalDeltas format
const ConsensusV27 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/d050b3cade6d5c664df8bd729bf219f179812595",
)

// ConsensusV28 introduces new TEAL features, larger program size, fee pooling and longer asset max URL
const ConsensusV28 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/65b4ab3266c52c56a0fa7d591754887d68faad0a",
)

// ConsensusV29 fixes application update by using ExtraProgramPages in size calculations
const ConsensusV29 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/abc54f79f9ad679d2d22f0fb9909fb005c16f8a1",
)

// ConsensusV30 introduces AVM 1.0 and TEAL 5, increases the app opt in limit to 50,
// and allows costs to be pooled in grouped stateful transactions.
const ConsensusV30 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/bc36005dbd776e6d1eaf0c560619bb183215645c",
)

// ConsensusV31 enables the batch verification for ed25519 signatures, Fix reward calculation issue, introduces the ability
// to force an expired participation offline, enables TEAL 6 ( AVM 1.1 ) and add support for creating
// state proof keys.
const ConsensusV31 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/85e6db1fdbdef00aa232c75199e10dc5fe9498f6",
)

// ConsensusV32 enables the unlimited assets.
const ConsensusV32 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/d5ac876d7ede07367dbaa26e149aa42589aac1f7",
)

// ConsensusV33 enables large blocks, the deeper block history for TEAL
// and catchpoint generation round after lowering in-memory deltas size (320 -> 4).
const ConsensusV33 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/830a4e673148498cc7230a0d1ba1ed0a5471acc6",
)

// ConsensusV34 enables the TEAL v7 opcodes, stateproofs, shorter lambda to 1.7s.
const ConsensusV34 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/2dd5435993f6f6d65691140f592ebca5ef19ffbd",
)

// ConsensusV35 updates the calculation of total stake in state proofs.
const ConsensusV35 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/433d8e9a7274b6fca703d91213e05c7e6a589e69",
)

// ConsensusV36 adds box storage in TEAL v8
const ConsensusV36 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf3c108d51f0eadb6",
)

// ConsensusV37 is a technical upgrade and released in the same time as ConsensusV38.
// It is needed to allow nodes to build up a necessary state to support state proofs related
// options in ConsensusV38
const ConsensusV37 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/1ac4dd1f85470e1fb36c8a65520e1313d7dfed5e",
)

// ConsensusV38 enables state proof verification using a special tracker,
// TEAL v9 resources sharing, pre-check ECDSA curve and extra features, and
// shortens the lambda to 1.5s.
const ConsensusV38 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/abd3d4823c6f77349fc04c3af7b1e99fe4df699f",
)

// ConsensusV39 enables dynamic filter timeouts, a deadline timeout of 4 seconds,
// TEAL v10 logicSig opcode budget pooling along with elliptic curve ops on some pairing friendly curves.
const ConsensusV39 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/925a46433742afb0b51bb939354bd907fa88bf95",
)

// ConsensusV40 enables consensus incentives and TEAL v11 featuring the mimc opcode
const ConsensusV40 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/236dcc18c9c507d794813ab768e467ea42d1b4d9",
)

// ConsensusV41 enables txn access, Sha512BlockHash, AppVersioning and TEAL v12 including the falcon verify opcode
const ConsensusV41 = ConsensusVersion(
	"https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed",
)

// ConsensusFuture is a protocol that should not appear in any production
// network, but is used to test features before they are released.
const ConsensusFuture = ConsensusVersion(
	"future",
)

// ConsensusVAlpha1 is the first consensus protocol for AlphaNet, which is the same as
// v32, but with a 2-second filter timeout and 5M block size.
const ConsensusVAlpha1 = ConsensusVersion("alpha1")

// ConsensusVAlpha2 is the second consensus protocol for AlphaNet, which increases the
// filter timeout to 3.5 seconds and uses 5MiB blocks.
const ConsensusVAlpha2 = ConsensusVersion("alpha2")

// ConsensusVAlpha3 uses the same parameters as ConsensusV33.
const ConsensusVAlpha3 = ConsensusVersion("alpha3")

// ConsensusVAlpha4 uses the same parameters as ConsensusV34.
const ConsensusVAlpha4 = ConsensusVersion("alpha4")

// ConsensusVAlpha5 uses the same parameters as ConsensusV36.
const ConsensusVAlpha5 = ConsensusVersion("alpha5")

// !!! ********************* !!!
// !!! *** Please update ConsensusCurrentVersion when adding new protocol versions *** !!!
// !!! ********************* !!!

// ConsensusCurrentVersion is the latest version and should be used
// when a specific version is not provided.
const ConsensusCurrentVersion = ConsensusV41

// Error is used to indicate that an unsupported protocol has been detected.
type Error ConsensusVersion

// Error satisfies builtin interface `error`
func (err Error) Error() string {
	proto := ConsensusVersion(err)
	return fmt.Sprintf("protocol not supported: %s", proto)
}
