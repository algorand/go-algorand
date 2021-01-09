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

package agreement

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand/data/bookkeeping"
)

// A Certificate contains a cryptographic proof that agreement was reached on a
// given block in a given round.
//
// When a client first joins the network or has fallen behind and needs to catch
// up, certificates allow the client to verify that a block someone gives them
// is the real one.
type Certificate unauthenticatedBundle

// Authenticate returns nil if the Certificate authenticates the given Block;
// otherwise, it returns an error.
//
// Callers may want to cache the result of this check, as it is relatively
// expensive.
func (c Certificate) Authenticate(e bookkeeping.Block, l LedgerReader, avv *AsyncVoteVerifier) (err error) {
	if c.Step != cert {
		return fmt.Errorf("certificate step is %v != Cert", c.Step)
	}
	err = c.claimsToAuthenticate(e)
	if err != nil {
		return
	}
	_, err = unauthenticatedBundle(c).verify(context.Background(), l, avv)
	return
}

// claimsToAuthenticate(b, r) checks whether this certificate claims that block b was agreed on in round r.
// Separately, the certificate itself will need to be checked, and its votes will need to be checked against a mu that's sufficiently up-to-date to get selection parameters.
// Fetching code could potentially do this part of the checking before the mu is caught up.
func (c Certificate) claimsToAuthenticate(e bookkeeping.Block) error {
	// Right round?
	if c.Round != e.Round() {
		return fmt.Errorf("certificate claims to validate the wrong round: %v != %v", c.Round, e.Round())
	}
	// Check that the block header's hash matches the cert
	if c.Proposal.BlockDigest != e.Digest() {
		return fmt.Errorf("certificate claims to validate the wrong hash: %v != %v", c.Proposal.BlockDigest, e.Digest())
	}
	return nil
}
