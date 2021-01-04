// Copyright (C) 2019-2021 Algorand, Inc.
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

package auction

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// This file defines the messages that appear on the blockchain
// (in Note fields of transactions).
//
// An auction consists of the following messages, in order:
//
// + A SignedParams message, starting an auction, and specifying, among
//   other things, the first block in which deposits can appear, and the
//   first block in which bids can appear (potentially later than the
//   first deposit block).
//
// + A set of zero or more SignedDeposit and SignedBid messages.
//
//   - A SignedDeposit message deposits external currency (e.g., USD)
//     from a bank (e.g., CoinList) into an auction.
//
//   - A SignedBid message places a bid by a user that has already
//     deposited currency into this auction (with a SignedDeposit).
//
// + A SignedSettlement message, finishing the auction.

// Deposit represents a deposit of external currency with a bank
// like CoinList, for a specific auction number.
type Deposit struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// BidderKey is the hash of the bidder's public key, used to
	// authenticate bids paid for by this deposit.
	BidderKey crypto.Digest `codec:"key"`

	// WinningsAddress is the address to which the winning algos should
	// be sent to (Optional, if this field is empty, the address will be set
	// to BidderKey)
	WinningsAddress crypto.Digest `codec:"out"`

	// Currency indicates the amount of external currency deposited.
	Currency uint64 `codec:"cur"`

	// AuctionKey specifies the auction into which the currency is
	// being deposited.
	AuctionKey crypto.Digest `codec:"auc"`

	// AuctionID indicates the auction number for which this currency
	// has been deposited.
	AuctionID uint64 `codec:"aid"`

	// DepositID uniquely identifies this deposit within an auction
	// (identified by AuctionID), so that a deposit cannot be applied
	// multiple times in the same auction.
	DepositID uint64 `codec:"did"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (d Deposit) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AuctionDeposit, protocol.Encode(&d)
}

// WinningAddress returns the effective winning address
func (d Deposit) WinningAddress() crypto.Digest {
	if d.WinningsAddress.IsZero() {
		return d.BidderKey
	}
	return d.WinningsAddress
}

// SignedDeposit represents a signed deposit message.
type SignedDeposit struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Deposit represents the deposit being signed.
	Deposit Deposit `codec:"dep"`

	// Sig is a signature over the hash of Deposit by the external
	// bank's key (e.g., CoinList).
	Sig crypto.Signature `codec:"sig"`
}

// Bid represents a bid by a user as part of an auction.
type Bid struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// BidderKey identifies the bidder placing this bid.
	BidderKey crypto.Digest `codec:"bidder"`

	// BidCurrency specifies how much external currency the bidder
	// is putting in with this bid.
	BidCurrency uint64 `codec:"cur"`

	// MaxPrice specifies the maximum price, in units of external
	// currency per Algo, that the bidder is willing to pay.
	// This must be at least as high as the current price of the
	// auction in the block in which this bid appears.
	MaxPrice uint64 `codec:"price"`

	// BidID identifies this bid.  The first bid by a bidder (identified
	// by BidderKey) with a particular BidID on the blockchain will be
	// considered, preventing replay of bids.  Specifying a different
	// BidID allows the bidder to place multiple bids in an auction.
	BidID uint64 `codec:"id"`

	// AuctionKey specifies the auction for this bid.
	AuctionKey crypto.Digest `codec:"auc"`

	// AuctionID identifies the auction for which this bid is intended.
	AuctionID uint64 `codec:"aid"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (b Bid) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AuctionBid, protocol.Encode(&b)
}

// SignedBid represents a signed bid by a bidder.
type SignedBid struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Bid contains information about the bid.
	Bid Bid `codec:"bid"`

	// Sig is a signature by the bidder, as identified in the bid
	// (Bid.BidderKey) over the hash of the Bid.
	Sig crypto.Signature `codec:"sig"`
}

// BidderOutcome specifies the outcome of a particular bidder's participation
// in an auction.
type BidderOutcome struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// BidderKey indicates the bidder that participated in the auction.
	BidderKey crypto.Digest `codec:"key"`

	// AlgosWon indicates the number of MicroAlgos that were won
	// by this bidder.
	AlgosWon uint64 `codec:"alg"`

	// WinningsAddress is the address to which the winning algos will
	// be sent to
	WinningsAddress crypto.Digest `codec:"out"`

	// BidID indicates the ID of the successful bid.
	BidID uint64 `codec:"id"`
}

// BidOutcomes describes the outcome of an auction.
type BidOutcomes struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// AuctionKey is the public key for the series of auctions.
	AuctionKey crypto.Digest `codec:"auc"`

	// AuctionID specifies the auction in which these outcomes apply.
	AuctionID uint64 `codec:"aid"`

	// Price indicates the price, in units of external currency
	// per algo, at which this auction finished.
	Price uint64 `codec:"price"`

	// Cleared indicates whether the auction fully cleared.
	// It is the same as in the Settlement.
	Cleared bool `codec:"cleared"`

	// Outcomes is a list of bid outcomes, one for every placed bid
	// in the auction.
	Outcomes []BidderOutcome `codec:"outcomes,allocbound=-"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (o BidOutcomes) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AuctionOutcomes, protocol.Encode(&o)
}

// Settlement describes the outcome of an auction.
type Settlement struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// AuctionKey is the public key for the series of auctions.
	AuctionKey crypto.Digest `codec:"auc"`

	// AuctionID identifies the auction being settled.
	AuctionID uint64 `codec:"aid"`

	// Cleared indicates whether the auction fully cleared.
	// It is the same as in the BidOutcomes.
	Cleared bool `codec:"cleared"`

	// OutcomesHash is a hash of the BidOutcomes for this auction.
	// The pre-image (the actual BidOutcomes struct) should be published
	// out-of-band (e.g., on the web site of the Algorand company).
	OutcomesHash crypto.Digest `codec:"outhash"`

	// Canceled indicates that the auction was canceled.
	// When Canceled is true, clear and OutcomeHash are false and empty, respectively.
	Canceled bool `codec:"canceled"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (s Settlement) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AuctionSettlement, protocol.Encode(&s)
}

// SignedSettlement is a settlement signed by the auction operator
// (e.g., the Algorand company).
type SignedSettlement struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Settlement describes the outcome of an auction.
	Settlement Settlement `codec:"settle"`

	// Sig is a signature by the auction operator on the hash
	// of the Settlement struct above.
	Sig crypto.Signature `codec:"sig"`
}

// Params describes the parameters for a particular auction.
type Params struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// AuctionKey is the public key of the auction operator.
	// This is somewhat superfluous, because the Params struct
	// gets signed by the corresponding private key, so in order
	// to verify a SignedParams, the caller must already know
	// the correct AuctionKey to use.  However, having this field
	// here is useful to allow code to keep track of all auction
	// parameters (including the public key) using a Params struct.
	AuctionKey crypto.Digest `codec:"auc"`

	// AuctionID identifies the auction whose parameters are being
	// specified.
	AuctionID uint64 `codec:"aid"`

	// BankKey specifies the key of the external bank that will
	// be signing deposits.
	BankKey crypto.Digest `codec:"bank"`

	// DispensingKey specifies the public key of the account from
	// which auction winnings will be dispensed.
	DispensingKey crypto.Digest `codec:"dispense"`

	// LastPrice specifies the price at the end of the auction
	// (i.e., in the last chunk), in units of external currency
	// per Algo.  This is called ``reserve price'' in the design doc.
	LastPrice uint64 `codec:"lastprice"`

	// DepositRound specifies the first block in which deposits
	// will be considered.  This can be less than FirstRound to
	// allow the external bank (e.g., CoinList) to place deposits
	// for an auction before bidding begins.
	DepositRound uint64 `codec:"depositrnd"`

	// FirstRound specifies the first block in which bids will be
	// considered.
	FirstRound uint64 `codec:"firstrnd"`

	// PriceChunkRounds specifies the number of blocks for which
	// the price remains the same.  The auction proceeds in chunks
	// of PriceChunkRounds at a time, starting from FirstRound.
	PriceChunkRounds uint64 `codec:"chunkrnds"`

	// NumChunks specifies the number of PriceChunkRounds-sized
	// chunks for which the auction will run.  This means that
	// the last block in which a bid can be placed will be
	// (FirstRound + PriceChunkRounds*NumChunnks - 1).
	NumChunks uint64 `codec:"numchunks"`

	// MaxPriceMultiple defines the ratio between MaxPrice (the
	// starting price of the auction) and LastPrice.  Expect this
	// is on the order of 100.
	MaxPriceMultiple uint64 `codec:"maxmult"`

	// NumAlgos specifies the maximum number of MicroAlgos that will be
	// sold in this auction.
	NumAlgos uint64 `codec:"maxalgos"`

	// MinBidAlgos specifies the minimum amount of a bid, in terms
	// of the number of MicroAlgos at the bid's maximum price.  This
	// should not be less than MinBalance, otherwise the transaction
	// that dispenses winnings might be rejected.
	MinBidAlgos uint64 `codec:"minbidalgos"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (p Params) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AuctionParams, protocol.Encode(&p)
}

// SignedParams is a signed statement by the auction operator attesting
// to the start of an auction.
type SignedParams struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Params specifies the parameters for the auction.
	Params Params `codec:"param"`

	// Sig is a signature over Params by the operator's key.
	Sig crypto.Signature `codec:"sig"`
}

// NoteFieldType indicates a type of auction message encoded into a
// transaction's Note field.
type NoteFieldType string

const (
	// NoteDeposit indicates a SignedDeposit message.
	NoteDeposit NoteFieldType = "d"

	// NoteBid indicates a SignedBid message.
	NoteBid NoteFieldType = "b"

	// NoteSettlement indicates a SignedSettlement message.
	NoteSettlement NoteFieldType = "s"

	// NoteParams indicates a SignedParams message.
	NoteParams NoteFieldType = "p"
)

// NoteField is the struct that represents an auction message.
type NoteField struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Type indicates which type of a message this is
	Type NoteFieldType `codec:"t"`

	// SignedDeposit, for NoteDeposit type
	SignedDeposit SignedDeposit `codec:"d"`

	// SignedBid, for NoteBid type
	SignedBid SignedBid `codec:"b"`

	// SignedSettlement, for NoteSettlement type
	SignedSettlement SignedSettlement `codec:"s"`

	// SignedParams, for NoteParams type
	SignedParams SignedParams `codec:"p"`
}

// MasterInput describes an input to an auction, used to feed auction deposits
// and bids into the auctionmaster tool.
type MasterInput struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Round indicates the round number in which this input appeared.
	Round uint64 `codec:"rnd"`

	// Type indicates whether this is a deposit or a bid.  Only deposit
	// and bid field types are valid here.
	Type NoteFieldType `codec:"t"`

	// SignedDeposit, for NoteDeposit type.
	SignedDeposit SignedDeposit `codec:"d"`

	// SignedBid, for NoteBid type.
	SignedBid SignedBid `codec:"b"`
}
