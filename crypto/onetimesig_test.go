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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
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

// copied from basics to avoid circular dependency
func oneTimeIDForRound(round uint64, keyDilution uint64) OneTimeSignatureIdentifier {
	return OneTimeSignatureIdentifier{
		Batch:  round / keyDilution,
		Offset: round % keyDilution,
	}
}

// Tests that we have the expected batch and offsets.
func TestOneTimeSignatureSecrets_DeleteBeforeFineGrained(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dilution := uint64(1000)

	testcases := []struct {
		name                string
		startBatch          uint64
		dilution            uint64
		round               int
		expectedBatches     int
		expectedOffsets     int
		expectedFirstBatch  uint64
		expectedFirstOffset uint64
	}{
		{
			name:                "no delete",
			dilution:            dilution,
			round:               -1, // no delete
			expectedBatches:     int(dilution),
			expectedOffsets:     0,
			expectedFirstBatch:  0,
			expectedFirstOffset: 0,
		}, {
			name:                "expand first batch",
			dilution:            dilution,
			round:               0,
			expectedBatches:     int(dilution) - 1,
			expectedOffsets:     int(dilution),
			expectedFirstBatch:  1,
			expectedFirstOffset: 0,
		}, {
			name:                "delete half of first batch",
			dilution:            dilution,
			round:               int(dilution / 2),
			expectedBatches:     int(dilution) - 1,
			expectedOffsets:     int(dilution) / 2,
			expectedFirstBatch:  1,
			expectedFirstOffset: dilution / 2,
		}, {
			name:                "expand second batch",
			dilution:            dilution,
			round:               int(dilution),
			expectedBatches:     int(dilution) - 2,
			expectedOffsets:     int(dilution),
			expectedFirstBatch:  2,
			expectedFirstOffset: 0,
		}, {
			name:                "halfway into 10th batch",
			dilution:            dilution,
			round:               int(9*dilution + dilution/2),
			expectedBatches:     int(dilution) - 10,
			expectedOffsets:     int(dilution) / 2,
			expectedFirstBatch:  10,
			expectedFirstOffset: dilution / 2,
		}, {
			name:                "delete all but last offset",
			dilution:            dilution,
			round:               int(dilution - 1),
			expectedBatches:     int(dilution) - 1,
			expectedOffsets:     1,
			expectedFirstBatch:  1,
			expectedFirstOffset: dilution - 1,
		}, {
			name:                "delete all but one",
			dilution:            dilution,
			round:               int(dilution*dilution) - 1,
			expectedBatches:     0,
			expectedOffsets:     1,
			expectedFirstBatch:  dilution,
			expectedFirstOffset: dilution - 1,
		}, {
			name:                "delete everything",
			dilution:            dilution,
			round:               int(dilution * dilution),
			expectedBatches:     0,
			expectedOffsets:     0,
			expectedFirstBatch:  dilution,
			expectedFirstOffset: 0,
		}, {
			name:                "non-zero start batch - expanded",
			startBatch:          32_000,
			dilution:            dilution,
			round:               int(32_000 * dilution),
			expectedBatches:     999,
			expectedOffsets:     int(dilution),
			expectedFirstBatch:  32_000 + 1,
			expectedFirstOffset: 0,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := GenerateOneTimeSignatureSecrets(tc.startBatch, tc.dilution)

			if tc.round != -1 {
				c.DeleteBeforeFineGrained(oneTimeIDForRound(uint64(tc.round), tc.dilution), tc.dilution)
			}

			require.Len(t, c.Batches, tc.expectedBatches)
			require.Len(t, c.Offsets, tc.expectedOffsets)
			require.Equal(t, c.FirstBatch, tc.expectedFirstBatch)
			require.Equal(t, c.FirstOffset, tc.expectedFirstOffset)
		})
	}
}

func TestOneTimeSignatureSecrets_DeleteAllButFineGrained(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dilution := uint64(1000)

	testcases := []struct {
		name                string
		startBatch          uint64
		dilution            uint64
		round               uint64
		expectedFirstBatch  uint64
		expectedFirstOffset uint64
		err                 error
	}{
		{
			name:                "expand first batch",
			dilution:            dilution,
			round:               0,
			expectedFirstBatch:  1,
			expectedFirstOffset: 0,
		}, {
			name:                "delete half of first batch",
			dilution:            dilution,
			round:               dilution / 2,
			expectedFirstBatch:  1,
			expectedFirstOffset: dilution / 2,
		}, {
			name:                "expand second batch",
			dilution:            dilution,
			round:               dilution,
			expectedFirstBatch:  2,
			expectedFirstOffset: 0,
		}, {
			name:                "halfway into 10th batch",
			dilution:            dilution,
			round:               9*dilution + dilution/2,
			expectedFirstBatch:  10,
			expectedFirstOffset: dilution / 2,
		}, {
			name:                "delete all but last offset",
			dilution:            dilution,
			round:               dilution - 1,
			expectedFirstBatch:  1,
			expectedFirstOffset: dilution - 1,
		}, {
			name:                "delete all but one",
			dilution:            dilution,
			round:               dilution*dilution - 1,
			expectedFirstBatch:  dilution,
			expectedFirstOffset: dilution - 1,
		}, {
			name:                "delete everything",
			dilution:            dilution,
			round:               dilution * dilution,
			expectedFirstBatch:  dilution,
			expectedFirstOffset: 0,
			err:                 ErrIdentifierNotInCurrentBatch,
		}, {
			name:                "non-zero start batch - expanded",
			startBatch:          32_000,
			dilution:            dilution,
			round:               32_000 * dilution,
			expectedFirstBatch:  32_000 + 1,
			expectedFirstOffset: 0,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := GenerateOneTimeSignatureSecrets(tc.startBatch, tc.dilution)

			id := oneTimeIDForRound(tc.round, tc.dilution)
			c.DeleteBeforeFineGrained(id, tc.dilution)
			err := c.DeleteAllButFineGrained(id)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
				return
			}

			require.Len(t, c.Batches, 0, "All batches are deleted.")
			require.Len(t, c.Offsets, 1, "All but one offset is deleted.")
			require.Equal(t, c.FirstBatch, tc.expectedFirstBatch)
			require.Equal(t, c.FirstOffset, tc.expectedFirstOffset)
		})
	}
}

func TestTruncatedSecretPanic(t *testing.T) {

	dilution := uint64(1000)
	c := GenerateOneTimeSignatureSecrets(0, dilution)

	id := oneTimeIDForRound(2500, dilution)
	c.DeleteBeforeFineGrained(id, dilution)

	require.False(t, c.truncated, "The object is not truncated yet.")
	require.NotPanics(t, func() { c.Snapshot() }, "Snapshot should not panic if the object is not truncated")

	err := c.DeleteAllButFineGrained(id)
	require.NoError(t, err)

	require.True(t, c.truncated, "DeleteAllbutFineGrained should mark the object as truncated")
	require.Panics(t, func() { c.Snapshot() }, "Snapshot should panic on truncated object")
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
