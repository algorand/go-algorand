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

// HashID is a domain separation prefix for an object type that might be hashed
// This ensures, for example, the hash of a transaction will never collide with the hash of a vote
type HashID string

// Hash IDs for specific object types, in lexicographic order.
// Hash IDs must be PREFIX-FREE (no hash ID is a prefix of another).
const (
	AppIndex HashID = "appID"

	// ARCReserved is used to reserve prefixes starting with `arc` to
	// ARCs-related hashes https://github.com/algorandfoundation/ARCs
	// The prefix for ARC-XXXX should start with:
	// "arcXXXX" (where "XXXX" is the 0-padded number of the ARC)
	// For example ARC-0003 can use any prefix starting with "arc0003"
	ARCReserved HashID = "arc"

	AuctionBid        HashID = "aB"
	AuctionDeposit    HashID = "aD"
	AuctionOutcomes   HashID = "aO"
	AuctionParams     HashID = "aP"
	AuctionSettlement HashID = "aS"

	AgreementSelector                HashID = "AS"
	BlockHeader256                   HashID = "B256"
	BlockHeader                      HashID = "BH"
	BalanceRecord                    HashID = "BR"
	Credential                       HashID = "CR"
	Genesis                          HashID = "GE"
	KeysInMSS                        HashID = "KP"
	MerkleArrayNode                  HashID = "MA"
	MerkleVectorCommitmentBottomLeaf HashID = "MB"
	Message                          HashID = "MX"
	MultisigProgram                  HashID = "MsigProgram"
	NetIdentityChallenge             HashID = "NIC"
	NetIdentityChallengeResponse     HashID = "NIR"
	NetIdentityVerificationMessage   HashID = "NIV"
	NetPrioResponse                  HashID = "NPR"
	OnlineAccount                    HashID = "OA"
	OnlineRoundParams                HashID = "ORP"
	OneTimeSigKey1                   HashID = "OT1"
	OneTimeSigKey2                   HashID = "OT2"
	PaysetFlat                       HashID = "PF"
	Payload                          HashID = "PL"
	Program                          HashID = "Program"
	ProgramData                      HashID = "ProgData"
	ProposerSeed                     HashID = "PS"
	ParticipationKeys                HashID = "PK"
	Seed                             HashID = "SD"
	SpecialAddr                      HashID = "SpecialAddr"
	SignedTxnInBlock                 HashID = "STIB"

	StateProofCoin    HashID = "spc"
	StateProofMessage HashID = "spm"
	StateProofPart    HashID = "spp"
	StateProofSig     HashID = "sps"
	StateProofVerCtx  HashID = "spv"

	TestHashable  HashID = "TE"
	TxGroup       HashID = "TG"
	TxnMerkleLeaf HashID = "TL"
	Transaction   HashID = "TX"
	Vote          HashID = "VO"
)
