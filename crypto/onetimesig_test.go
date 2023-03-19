// Copyright (C) 2019-2023 Algorand, Inc.
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
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func randID() OneTimeSignatureIdentifier {
	return OneTimeSignatureIdentifier{
		Batch: RandUint64() % 256,

		// Avoid generating the last few offsets (in a batch size of 256), so we can increment correctly
		Offset: RandUint64() % 250,
	}
}

func TestOneTimeSignVerifyNewStyle(t *testing.T) {
	partitiontest.PartitionTest(t)
	c := GenerateOneTimeSignatureSecrets(0, 1000)
	c2 := GenerateOneTimeSignatureSecrets(0, 1000)
	testOneTimeSignVerifyNewStyle(t, c, c2)
}

func testOneTimeSignVerifyNewStyle(t *testing.T, c *OneTimeSignatureSecrets, c2 *OneTimeSignatureSecrets) {
	id := randID()
	s := randString()
	s2 := randString()

	sig := c.Sign(id, s)
	if !c.Verify(id, s, sig) {
		t.Errorf("correct signature failed to verify (ephemeral)")
	}

	if c.Verify(id, s2, sig) {
		t.Errorf("signature verifies on wrong message")
	}

	sig2 := c2.Sign(id, s)
	if c.Verify(id, s, sig2) {
		t.Errorf("wrong master key incorrectly verified (ephemeral)")
	}

	otherID := randID()
	if c.Verify(otherID, s, sig) {
		t.Errorf("signature verifies for wrong ID")
	}

	nextOffsetID := id
	nextOffsetID.Offset++
	if c.Verify(nextOffsetID, s, sig) {
		t.Errorf("signature verifies after changing offset")
	}

	c.DeleteBeforeFineGrained(nextOffsetID, 256)
	sigAfterDelete := c.Sign(id, s)
	if c.Verify(id, s, sigAfterDelete) { // TODO(adam): Previously, this call to Verify was verifying old-style coarse-grained one-time signatures. Now it's verifying new-style fine-grained one-time signatures. Is this correct?
		t.Errorf("signature verifies after delete offset")
	}

	sigNextAfterDelete := c.Sign(nextOffsetID, s)
	if !c.Verify(nextOffsetID, s, sigNextAfterDelete) {
		t.Errorf("signature fails to verify after deleting up to this offset")
	}

	nextOffsetID.Offset++
	sigNext2AfterDelete := c.Sign(nextOffsetID, s)
	if !c.Verify(nextOffsetID, s, sigNext2AfterDelete) {
		t.Errorf("signature fails to verify after deleting up to previous offset")
	}

	nextBatchID := id
	nextBatchID.Batch++

	nextBatchOffsetID := nextBatchID
	nextBatchOffsetID.Offset++
	c.DeleteBeforeFineGrained(nextBatchOffsetID, 256)
	sigAfterDelete = c.Sign(nextBatchID, s)
	if c.Verify(nextBatchID, s, sigAfterDelete) {
		t.Errorf("signature verifies after delete")
	}

	sigNextAfterDelete = c.Sign(nextBatchOffsetID, s)
	if !c.Verify(nextBatchOffsetID, s, sigNextAfterDelete) {
		t.Errorf("signature fails to verify after delete up to this offset")
	}

	nextBatchOffsetID.Offset++
	sigNext2AfterDelete = c.Sign(nextBatchOffsetID, s)
	if !c.Verify(nextBatchOffsetID, s, sigNext2AfterDelete) {
		t.Errorf("signature fails to verify after delete up to previous offset")
	}

	// Jump by two batches
	bigJumpID := nextBatchOffsetID
	bigJumpID.Batch += 10
	c.DeleteBeforeFineGrained(bigJumpID, 256)

	preBigJumpID := bigJumpID
	preBigJumpID.Batch--
	if c.Verify(preBigJumpID, s, c.Sign(preBigJumpID, s)) {
		t.Errorf("preBigJumpID verifies")
	}

	preBigJumpID.Batch++
	preBigJumpID.Offset--
	if c.Verify(preBigJumpID, s, c.Sign(preBigJumpID, s)) {
		t.Errorf("preBigJumpID verifies")
	}

	if !c.Verify(bigJumpID, s, c.Sign(bigJumpID, s)) {
		t.Errorf("bigJumpID does not verify")
	}

	bigJumpID.Offset++
	if !c.Verify(bigJumpID, s, c.Sign(bigJumpID, s)) {
		t.Errorf("bigJumpID.Offset++ does not verify")
	}

	bigJumpID.Batch++
	if !c.Verify(bigJumpID, s, c.Sign(bigJumpID, s)) {
		t.Errorf("bigJumpID.Batch++ does not verify")
	}
}

func TestOneTimeSignBatchVerifyNewStyle(t *testing.T) {
	partitiontest.PartitionTest(t)

	verifiers := make([]OneTimeSignatureVerifier, 0, 16)
	ids := make([]OneTimeSignatureIdentifier, 0, 16)
	messages := make([]Hashable, 0, 16)
	sigs := make([]OneTimeSignature, 0, 16)

	c := GenerateOneTimeSignatureSecrets(0, 1000)
	c2 := GenerateOneTimeSignatureSecrets(0, 1000)

	id := randID()
	s := randString()
	s2 := randString()

	sig := c.Sign(id, s)
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, id)
	messages = append(messages, s)
	sigs = append(sigs, sig)
	if !c.Verify(id, s, sig) {
		t.Errorf("correct signature failed to verify (ephemeral)")
	}

	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, id)
	messages = append(messages, s2)
	sigs = append(sigs, sig)
	if c.Verify(id, s2, sig) {
		t.Errorf("signature verifies on wrong message")
	}

	sig2 := c2.Sign(id, s)
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, id)
	messages = append(messages, s)
	sigs = append(sigs, sig2)
	if c.Verify(id, s, sig2) {
		t.Errorf("wrong master key incorrectly verified (ephemeral)")
	}

	otherID := randID()
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, otherID)
	messages = append(messages, s)
	sigs = append(sigs, sig)
	if c.Verify(otherID, s, sig) {
		t.Errorf("signature verifies for wrong ID")
	}

	nextOffsetID := id
	nextOffsetID.Offset++
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, nextOffsetID)
	messages = append(messages, s)
	sigs = append(sigs, sig)
	if c.Verify(nextOffsetID, s, sig) {
		t.Errorf("signature verifies after changing offset")
	}

	c.DeleteBeforeFineGrained(nextOffsetID, 256)
	sigAfterDelete := c.Sign(id, s)
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, id)
	messages = append(messages, s)
	sigs = append(sigs, sigAfterDelete)
	if c.Verify(id, s, sigAfterDelete) { // TODO(adam): Previously, this call to Verify was verifying old-style coarse-grained one-time signatures. Now it's verifying new-style fine-grained one-time signatures. Is this correct?
		t.Errorf("signature verifies after delete offset")
	}

	sigNextAfterDelete := c.Sign(nextOffsetID, s)
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, nextOffsetID)
	messages = append(messages, s)
	sigs = append(sigs, sigNextAfterDelete)
	if !c.Verify(nextOffsetID, s, sigNextAfterDelete) {
		t.Errorf("signature fails to verify after deleting up to this offset")
	}

	nextOffsetID.Offset++
	sigNext2AfterDelete := c.Sign(nextOffsetID, s)
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, nextOffsetID)
	messages = append(messages, s)
	sigs = append(sigs, sigNext2AfterDelete)
	if !c.Verify(nextOffsetID, s, sigNext2AfterDelete) {
		t.Errorf("signature fails to verify after deleting up to previous offset")
	}

	nextBatchID := id
	nextBatchID.Batch++

	nextBatchOffsetID := nextBatchID
	nextBatchOffsetID.Offset++
	c.DeleteBeforeFineGrained(nextBatchOffsetID, 256)
	sigAfterDelete2 := c.Sign(nextBatchID, s)
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, nextBatchID)
	messages = append(messages, s)
	sigs = append(sigs, sigAfterDelete2)
	if c.Verify(nextBatchID, s, sigAfterDelete2) {
		t.Errorf("signature verifies after delete")
	}

	sigNextAfterDelete2 := c.Sign(nextBatchOffsetID, s)
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, nextBatchOffsetID)
	messages = append(messages, s)
	sigs = append(sigs, sigNextAfterDelete2)
	if !c.Verify(nextBatchOffsetID, s, sigNextAfterDelete2) {
		t.Errorf("signature fails to verify after delete up to this offset")
	}

	nextBatchOffsetID.Offset++
	sigNext2AfterDelete2 := c.Sign(nextBatchOffsetID, s)
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, nextBatchOffsetID)
	messages = append(messages, s)
	sigs = append(sigs, sigNext2AfterDelete2)
	if !c.Verify(nextBatchOffsetID, s, sigNext2AfterDelete2) {
		t.Errorf("signature fails to verify after delete up to previous offset")
	}

	// Jump by two batches
	bigJumpID := nextBatchOffsetID
	bigJumpID.Batch += 10
	c.DeleteBeforeFineGrained(bigJumpID, 256)

	preBigJumpID := bigJumpID
	preBigJumpID.Batch--
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, preBigJumpID)
	messages = append(messages, s)
	sigs = append(sigs, c.Sign(preBigJumpID, s))
	if c.Verify(preBigJumpID, s, c.Sign(preBigJumpID, s)) {
		t.Errorf("preBigJumpID verifies")
	}

	preBigJumpID.Batch++
	preBigJumpID.Offset--
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, preBigJumpID)
	messages = append(messages, s)
	sigs = append(sigs, c.Sign(preBigJumpID, s))
	if c.Verify(preBigJumpID, s, c.Sign(preBigJumpID, s)) {
		t.Errorf("preBigJumpID verifies")
	}

	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, bigJumpID)
	messages = append(messages, s)
	sigs = append(sigs, c.Sign(bigJumpID, s))
	if !c.Verify(bigJumpID, s, c.Sign(bigJumpID, s)) {
		t.Errorf("bigJumpID does not verify")
	}

	bigJumpID.Offset++
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, bigJumpID)
	messages = append(messages, s)
	sigs = append(sigs, c.Sign(bigJumpID, s))
	if !c.Verify(bigJumpID, s, c.Sign(bigJumpID, s)) {
		t.Errorf("bigJumpID.Offset++ does not verify")
	}

	bigJumpID.Batch++
	verifiers = append(verifiers, c.OneTimeSignatureVerifier)
	ids = append(ids, bigJumpID)
	messages = append(messages, s)
	sigs = append(sigs, c.Sign(bigJumpID, s))
	if !c.Verify(bigJumpID, s, c.Sign(bigJumpID, s)) {
		t.Errorf("bigJumpID.Batch++ does not verify")
	}

	results := BatchVerifyOneTimeSignatures(verifiers, ids, messages, sigs)

	require.False(t, results[0], "correct signature failed to verify (ephemeral)")
	require.True(t, results[1], "signature verifies on wrong message")
	require.True(t, results[2], "wrong master key incorrectly verified (ephemeral)")
	require.True(t, results[3], "signature verifies for wrong ID")
	require.True(t, results[4], "signature verifies after changing offset")
	require.True(t, results[5], "signature verifies after delete offset")
	require.False(t, results[6], "signature fails to verify after deleting up to this offset")
	require.False(t, results[7], "signature fails to verify after deleting up to previous offset")
	require.True(t, results[8], "signature verifies after delete")
	require.False(t, results[9], "signature fails to verify after delete up to this offset")
	require.False(t, results[10], "signature fails to verify after delete up to previous offset")
	require.True(t, results[11], "preBigJumpID verifies")
	require.True(t, results[12], "preBigJumpID verifies")
	require.False(t, results[13], "bigJumpID does not verify")
	require.False(t, results[14], "bigJumpID.Offset++ does not verify")
	require.False(t, results[15], "bigJumpID.Batch++ does not verify")

}

func BenchmarkOneTimeSigBatchVerification(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprintf("batch=%v", enabled), func(b *testing.B) {
			// generate a bunch of signatures
			c := GenerateOneTimeSignatureSecrets(0, 1000)
			sigs := make([]OneTimeSignature, b.N)
			ids := make([]OneTimeSignatureIdentifier, b.N)
			msg := randString()

			for i := 0; i < b.N; i++ {
				ids[i] = randID()
				sigs[i] = c.Sign(ids[i], msg)
			}

			v := c.OneTimeSignatureVerifier
			// verify them
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				v.Verify(ids[i], msg, sigs[i])
			}
		})
	}
}
