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

package crypto

import (
	"testing"
)

func randID() OneTimeSignatureIdentifier {
	return OneTimeSignatureIdentifier{
		Batch: RandUint64() % 256,

		// Avoid generating the last few offsets (in a batch size of 256), so we can increment correctly
		Offset: RandUint64() % 250,
	}
}

func TestOneTimeSignVerifyOldStyle(t *testing.T) {
	c := GenerateOneTimeSignatureSecrets(0, 1000)
	c2 := GenerateOneTimeSignatureSecrets(0, 1000)

	id := randID()
	s := randString()
	s2 := randString()

	sig := c.Sign(id, false, s)
	if !c.Verify(id, false, s, sig) {
		t.Errorf("correct signature failed to verify (ephemeral)")
	}

	if c.Verify(id, false, s2, sig) {
		t.Errorf("signature verifies on wrong message")
	}

	sig2 := c2.Sign(id, false, s)
	if c.Verify(id, false, s, sig2) {
		t.Errorf("wrong master key incorrectly verified (ephemeral)")
	}

	otherID := randID()
	for otherID.Batch == id.Batch {
		// Enforce that the Batch ID be different;
		// otherwise this test may fail spuriously
		otherID = randID()
	}
	if c.Verify(otherID, false, s, sig) {
		t.Errorf("signature verifies for wrong ID")
	}

	nextOffsetID := id
	nextOffsetID.Offset++
	if !c.Verify(nextOffsetID, false, s, sig) {
		t.Errorf("correct signature failed to verify after bumping batch (should be irrelevant when coarse-grained)")
	}

	nextID := id
	nextID.Batch++
	c.DeleteBeforeCoarseGrained(nextID)
	sigAfterDelete := c.Sign(id, false, s)
	if c.Verify(id, false, s, sigAfterDelete) {
		t.Errorf("signature verifies after delete")
	}

	sigNextAfterDelete := c.Sign(nextID, false, s)
	if !c.Verify(nextID, false, s, sigNextAfterDelete) {
		t.Errorf("correct signature for nextID failed to verify")
	}
}

func TestOneTimeSignVerifyNewStyle(t *testing.T) {
	c := GenerateOneTimeSignatureSecrets(0, 1000)
	c2 := GenerateOneTimeSignatureSecrets(0, 1000)
	testOneTimeSignVerifyNewStyle(t, c, c2)
}

func TestOneTimeSignVerifyMixedStyle(t *testing.T) {
	c := GenerateOneTimeSignatureSecrets(0, 1000)
	c2 := GenerateOneTimeSignatureSecrets(0, 1000)

	// Wipe out PKSigNew from subkeys
	for i := range c.Batches {
		c.Batches[i].PKSigNew = ed25519Signature{}
	}
	for i := range c2.Batches {
		c2.Batches[i].PKSigNew = ed25519Signature{}
	}

	testOneTimeSignVerifyNewStyle(t, c, c2)
}

func testOneTimeSignVerifyNewStyle(t *testing.T, c *OneTimeSignatureSecrets, c2 *OneTimeSignatureSecrets) {
	id := randID()
	s := randString()
	s2 := randString()

	sig := c.Sign(id, true, s)
	if !c.Verify(id, true, s, sig) {
		t.Errorf("correct signature failed to verify (ephemeral)")
	}

	if c.Verify(id, true, s2, sig) {
		t.Errorf("signature verifies on wrong message")
	}

	sig2 := c2.Sign(id, true, s)
	if c.Verify(id, true, s, sig2) {
		t.Errorf("wrong master key incorrectly verified (ephemeral)")
	}

	otherID := randID()
	if c.Verify(otherID, true, s, sig) {
		t.Errorf("signature verifies for wrong ID")
	}

	nextOffsetID := id
	nextOffsetID.Offset++
	if c.Verify(nextOffsetID, true, s, sig) {
		t.Errorf("signature verifies after changing offset")
	}

	c.DeleteBeforeFineGrained(nextOffsetID, 256)
	sigAfterDelete := c.Sign(id, true, s)
	if c.Verify(id, false, s, sigAfterDelete) {
		t.Errorf("signature verifies after delete offset")
	}

	sigNextAfterDelete := c.Sign(nextOffsetID, true, s)
	if !c.Verify(nextOffsetID, true, s, sigNextAfterDelete) {
		t.Errorf("signature fails to verify after deleting up to this offset")
	}

	nextOffsetID.Offset++
	sigNext2AfterDelete := c.Sign(nextOffsetID, true, s)
	if !c.Verify(nextOffsetID, true, s, sigNext2AfterDelete) {
		t.Errorf("signature fails to verify after deleting up to previous offset")
	}

	nextBatchID := id
	nextBatchID.Batch++

	nextBatchOffsetID := nextBatchID
	nextBatchOffsetID.Offset++
	c.DeleteBeforeFineGrained(nextBatchOffsetID, 256)
	sigAfterDelete = c.Sign(nextBatchID, true, s)
	if c.Verify(nextBatchID, true, s, sigAfterDelete) {
		t.Errorf("signature verifies after delete")
	}

	sigNextAfterDelete = c.Sign(nextBatchOffsetID, true, s)
	if !c.Verify(nextBatchOffsetID, true, s, sigNextAfterDelete) {
		t.Errorf("signature fails to verify after delete up to this offset")
	}

	nextBatchOffsetID.Offset++
	sigNext2AfterDelete = c.Sign(nextBatchOffsetID, true, s)
	if !c.Verify(nextBatchOffsetID, true, s, sigNext2AfterDelete) {
		t.Errorf("signature fails to verify after delete up to previous offset")
	}

	// Jump by two batches
	bigJumpID := nextBatchOffsetID
	bigJumpID.Batch += 10
	c.DeleteBeforeFineGrained(bigJumpID, 256)

	preBigJumpID := bigJumpID
	preBigJumpID.Batch--
	if c.Verify(preBigJumpID, true, s, c.Sign(preBigJumpID, true, s)) {
		t.Errorf("preBigJumpID verifies")
	}

	preBigJumpID.Batch++
	preBigJumpID.Offset--
	if c.Verify(preBigJumpID, true, s, c.Sign(preBigJumpID, true, s)) {
		t.Errorf("preBigJumpID verifies")
	}

	if !c.Verify(bigJumpID, true, s, c.Sign(bigJumpID, true, s)) {
		t.Errorf("bigJumpID does not verify")
	}

	bigJumpID.Offset++
	if !c.Verify(bigJumpID, true, s, c.Sign(bigJumpID, true, s)) {
		t.Errorf("bigJumpID.Offset++ does not verify")
	}

	bigJumpID.Batch++
	if !c.Verify(bigJumpID, true, s, c.Sign(bigJumpID, true, s)) {
		t.Errorf("bigJumpID.Batch++ does not verify")
	}
}
