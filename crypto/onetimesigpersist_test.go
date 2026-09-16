// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// reassemble round-trips a snapshot through Header/Encoded*/FromRows.
func reassemble(t *testing.T, snap OneTimeSignatureSecretsPersistent) *OneTimeSignatureSecrets {
	t.Helper()
	restored, err := OneTimeSignatureSecretsFromRows(snap.Header(), snap.EncodedBatches(), snap.EncodedOffsets())
	require.NoError(t, err)
	return restored
}

// requireSameSecrets compares two secrets by their canonical msgpack encoding.
func requireSameSecrets(t *testing.T, expected, actual *OneTimeSignatureSecrets) {
	t.Helper()
	e := expected.Snapshot()
	a := actual.Snapshot()
	require.Equal(t, protocol.Encode(&e), protocol.Encode(&a))
}

// TestHeaderRoundTrip walks a key through its life (fresh, mid-batch, across
// several batch boundaries, exhausted), reassembling from header and rows at
// every step and checking the restored secrets still sign verifiably.
func TestHeaderRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const numKeysPerBatch = 8
	s := GenerateOneTimeSignatureSecrets(0, 6)
	pub := s.OneTimeSignatureVerifier

	// fresh: batch subkeys only
	hdr := s.Snapshot().Header()
	require.Equal(t, uint64(6), hdr.BatchCount)
	require.Zero(t, hdr.OffsetCount)
	require.False(t, hdr.Exhausted())
	requireSameSecrets(t, s, reassemble(t, s.Snapshot().OneTimeSignatureSecretsPersistent))

	msg := randString()
	for round := uint64(0); round < 4*numKeysPerBatch; round += 3 {
		id := OneTimeSignatureIdentifier{Batch: round / numKeysPerBatch, Offset: round % numKeysPerBatch}
		s.DeleteBeforeFineGrained(id, numKeysPerBatch)

		snap := s.Snapshot().OneTimeSignatureSecretsPersistent
		hdr = snap.Header()
		require.Equal(t, uint64(len(snap.Batches)), hdr.BatchCount)
		require.Equal(t, uint64(len(snap.Offsets)), hdr.OffsetCount)
		require.Equal(t, snap.FirstBatch-1, id.Batch, "offsets belong to batch FirstBatch-1")

		restored := reassemble(t, snap)
		require.Equal(t, pub, restored.OneTimeSignatureVerifier)
		sig := restored.Sign(id, msg)
		require.True(t, pub.Verify(id, msg, sig), "restored secrets failed to sign round %d", round)
		requireSameSecrets(t, s, restored)
	}

	// exhausted: both counts zero, nil slices after reassembly, and a later
	// far-future deletion does not bump FirstBatch (DeleteBeforeFineGrained
	// skips the bump only when Batches is nil)
	s.DeleteBeforeFineGrained(OneTimeSignatureIdentifier{Batch: 50}, numKeysPerBatch)
	hdr = s.Snapshot().Header()
	require.True(t, hdr.Exhausted())
	restored := reassemble(t, s.Snapshot().OneTimeSignatureSecretsPersistent)
	require.Nil(t, restored.Batches)
	require.Nil(t, restored.Offsets)
	restored.DeleteBeforeFineGrained(OneTimeSignatureIdentifier{Batch: 200}, numKeysPerBatch)
	require.Equal(t, hdr.FirstBatch, restored.FirstBatch)
}

func TestFromRowsValidation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const numKeysPerBatch = 16
	s := GenerateOneTimeSignatureSecrets(0, 10)
	s.DeleteBeforeFineGrained(OneTimeSignatureIdentifier{Batch: 2, Offset: 3}, numKeysPerBatch)
	snap := s.Snapshot().OneTimeSignatureSecretsPersistent
	hdr, batches, offsets := snap.Header(), snap.EncodedBatches(), snap.EncodedOffsets()
	require.NotEmpty(t, batches)
	require.NotEmpty(t, offsets)

	_, err := OneTimeSignatureSecretsFromRows(hdr, batches, offsets)
	require.NoError(t, err)

	// row count disagrees with the header
	_, err = OneTimeSignatureSecretsFromRows(hdr, batches[1:], offsets)
	require.ErrorContains(t, err, "missing or extra rows")
	_, err = OneTimeSignatureSecretsFromRows(hdr, batches, offsets[:len(offsets)-1])
	require.ErrorContains(t, err, "missing or extra rows")

	// gap in batch rows
	gapped := append([]KeyedSubkey{}, batches...)
	gapped[1].Index++
	_, err = OneTimeSignatureSecretsFromRows(hdr, gapped, offsets)
	require.ErrorContains(t, err, "batch row")

	// wrong anchor for offset rows
	shifted := append([]KeyedSubkey{}, offsets...)
	for i := range shifted {
		shifted[i].Index++
	}
	_, err = OneTimeSignatureSecretsFromRows(hdr, batches, shifted)
	require.ErrorContains(t, err, "offset row")

	// corrupt row bytes
	corrupt := append([]KeyedSubkey{}, batches...)
	corrupt[0].Key = []byte{0xff, 0x00, 0x01}
	_, err = OneTimeSignatureSecretsFromRows(hdr, corrupt, offsets)
	require.ErrorContains(t, err, "failed to decode")

	// offsets cannot exist before any batch was expanded
	noBatch := hdr
	noBatch.FirstBatch = 0
	_, err = OneTimeSignatureSecretsFromRows(noBatch, batches, offsets)
	require.ErrorContains(t, err, "FirstBatch is 0")
}

// TestSnapshotStableUnderConcurrentDelete verifies a snapshot stays
// internally consistent and usable while DeleteBeforeFineGrained (and Sign,
// as agreement does) run concurrently on the live secrets, under -race.
func TestSnapshotStableUnderConcurrentDelete(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const numKeysPerBatch = 8
	s := GenerateOneTimeSignatureSecrets(0, 64)
	pub := s.OneTimeSignatureVerifier
	msg := randString()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for round := uint64(0); round < 32*numKeysPerBatch; round++ {
			id := OneTimeSignatureIdentifier{Batch: round / numKeysPerBatch, Offset: round % numKeysPerBatch}
			s.DeleteBeforeFineGrained(id, numKeysPerBatch)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			snap := s.Snapshot().OneTimeSignatureSecretsPersistent
			restored := reassemble(t, snap)
			hdr := snap.Header()
			if hdr.OffsetCount > 0 {
				// the snapshot's first live offset must sign verifiably even if
				// the live secrets have since moved past it
				id := OneTimeSignatureIdentifier{Batch: hdr.FirstBatch - 1, Offset: hdr.FirstOffset}
				require.True(t, pub.Verify(id, msg, restored.Sign(id, msg)))
			}
		}
	}()
	go func() {
		defer wg.Done()
		for round := uint64(0); round < 16*numKeysPerBatch; round++ {
			id := OneTimeSignatureIdentifier{Batch: round / numKeysPerBatch, Offset: round % numKeysPerBatch}
			s.Sign(id, msg)
		}
	}()
	wg.Wait()
}
