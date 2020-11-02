// Copyright (C) 2019-2020 Algorand, Inc.
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

// Hash IDs for specific object types, in lexicographic order to avoid dups.
const (
	AuctionBid        HashID = "aB"
	AuctionDeposit    HashID = "aD"
	AuctionOutcomes   HashID = "aO"
	AuctionParams     HashID = "aP"
	AuctionSettlement HashID = "aS"

	CompactCertCoin HashID = "ccc"
	CompactCertPart HashID = "ccp"
	CompactCertSig  HashID = "ccs"

	AgreementSelector HashID = "AS"
	BlockHeader       HashID = "BH"
	BalanceRecord     HashID = "BR"
	Credential        HashID = "CR"
	Genesis           HashID = "GE"
	MerkleArrayNode   HashID = "MA"
	Message           HashID = "MX"
	NetPrioResponse   HashID = "NPR"
	OneTimeSigKey1    HashID = "OT1"
	OneTimeSigKey2    HashID = "OT2"
	PaysetFlat        HashID = "PF"
	Payload           HashID = "PL"
	Program           HashID = "Program"
	ProgramData       HashID = "ProgData"
	ProposerSeed      HashID = "PS"
	Seed              HashID = "SD"
	SpecialAddr       HashID = "SpecialAddr"
	TestHashable      HashID = "TE"
	TxGroup           HashID = "TG"
	Transaction       HashID = "TX"
	Vote              HashID = "VO"
)
