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
)

// VerifySignedParams checks the signature in a SignedParams object.
// The signature must verify against auctionKey.  This function does
// NOT, however, check that the AuctionID matches any particular
// value. The caller must verify AuctionID as needed.
func VerifySignedParams(sp SignedParams, auctionKey crypto.Digest) bool {
	if !crypto.SignatureVerifier(auctionKey).Verify(sp.Params, sp.Sig) {
		return false
	}

	if sp.Params.AuctionKey != auctionKey {
		return false
	}

	return true
}

// VerifySignedDeposit checks a SignedDeposit's signature, auction
// key, and auction ID against the Params data.
func (p Params) VerifySignedDeposit(sd SignedDeposit) bool {
	if !crypto.SignatureVerifier(p.BankKey).Verify(sd.Deposit, sd.Sig) {
		return false
	}

	if sd.Deposit.AuctionKey != p.AuctionKey || sd.Deposit.AuctionID != p.AuctionID {
		return false
	}

	return true
}

// VerifySignedBid checks a SignedBid's signature, auction key, and
// auction ID against the Params data.
func (p Params) VerifySignedBid(sb SignedBid) bool {
	if !crypto.SignatureVerifier(sb.Bid.BidderKey).Verify(sb.Bid, sb.Sig) {
		return false
	}

	if sb.Bid.AuctionKey != p.AuctionKey || sb.Bid.AuctionID != p.AuctionID {
		return false
	}

	return true
}

// VerifySignedSettlement checks a SignedSettlement's signature,
// auction key, and auction ID.
func VerifySignedSettlement(ss SignedSettlement, auctionKey crypto.Digest, auctionID uint64) bool {
	if !crypto.SignatureVerifier(auctionKey).Verify(ss.Settlement, ss.Sig) {
		return false
	}

	if ss.Settlement.AuctionKey != auctionKey || ss.Settlement.AuctionID != auctionID {
		return false
	}

	return true
}

// VerifySignedSettlement can also work on a Params object.
func (p Params) VerifySignedSettlement(ss SignedSettlement) bool {
	return VerifySignedSettlement(ss, p.AuctionKey, p.AuctionID)
}

// VerifyBidOutcomes checks that a BidOutcomes object matches a Settlement.
func (s Settlement) VerifyBidOutcomes(bo BidOutcomes) bool {
	if s.AuctionKey != bo.AuctionKey || s.AuctionID != bo.AuctionID {
		return false
	}

	if s.OutcomesHash != crypto.HashObj(bo) {
		return false
	}

	if s.Cleared != bo.Cleared {
		return false
	}

	return true
}
