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
	"fmt"

	"github.com/algorand/go-algorand/protocol"
)

//msgp:ignore KeyedSubkey

// KeyedSubkey is one ephemeral subkey prepared for row-oriented persistent
// storage.  Index is the absolute batch number for batch subkeys, or the
// absolute offset (within batch FirstBatch-1) for offset subkeys.  Key is the
// msgpack encoding of the subkey.
type KeyedSubkey struct {
	Index uint64
	Key   []byte
}

// PersistentState returns a copy of the persistent scalar fields (with the
// Batches and Offsets slices nil'ed out) plus the number of live batch and
// offset subkeys, captured atomically with respect to concurrent mutating
// calls (specifically, DeleteBefore*).  This is the cheap per-round probe for
// row-oriented storage: no subkey is encoded.
func (s *OneTimeSignatureSecrets) PersistentState() (scalars OneTimeSignatureSecretsPersistent, numBatches int, numOffsets int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.persistentScalarsLocked(), len(s.Batches), len(s.Offsets)
}

func (s *OneTimeSignatureSecrets) persistentScalarsLocked() OneTimeSignatureSecretsPersistent {
	scalars := s.OneTimeSignatureSecretsPersistent
	scalars.Batches = nil
	scalars.Offsets = nil
	return scalars
}

func (s *OneTimeSignatureSecrets) encodedBatchesLocked() []KeyedSubkey {
	if len(s.Batches) == 0 {
		return nil
	}
	batches := make([]KeyedSubkey, len(s.Batches))
	for i := range s.Batches {
		batches[i] = KeyedSubkey{
			Index: s.FirstBatch + uint64(i),
			Key:   protocol.Encode(&s.Batches[i]),
		}
	}
	return batches
}

func (s *OneTimeSignatureSecrets) encodedOffsetsLocked() []KeyedSubkey {
	if len(s.Offsets) == 0 {
		return nil
	}
	offsets := make([]KeyedSubkey, len(s.Offsets))
	for j := range s.Offsets {
		offsets[j] = KeyedSubkey{
			Index: s.FirstOffset + uint64(j),
			Key:   protocol.Encode(&s.Offsets[j]),
		}
	}
	return offsets
}

// OffsetsExpanded returns whether a batch has ever been expanded into offset
// subkeys: OffsetsPK2 is set on the first expansion and never cleared.  A key
// that was never expanded legitimately has no offset subkeys.
func (s *OneTimeSignatureSecretsPersistent) OffsetsExpanded() bool {
	return s.OffsetsPK2 != (ed25519PublicKey{})
}

// PersistentParts returns the scalar fields plus every subkey encoded as its
// own row, all captured atomically under a single lock acquisition so the
// scalars and rows are mutually consistent even while DeleteBefore* runs
// concurrently.  batches[i].Index == scalars.FirstBatch+i, and
// offsets[j].Index == scalars.FirstOffset+j (offset subkeys belong to batch
// scalars.FirstBatch-1).
func (s *OneTimeSignatureSecrets) PersistentParts() (scalars OneTimeSignatureSecretsPersistent, batches []KeyedSubkey, offsets []KeyedSubkey) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.persistentScalarsLocked(), s.encodedBatchesLocked(), s.encodedOffsetsLocked()
}

// PersistentScalarsAndOffsets is PersistentParts without encoding the batch
// subkeys.  Batch rows are immutable in storage after the initial insert
// (they are only ever deleted), so steady-state persistence such as a batch
// rollover never needs them re-encoded.
func (s *OneTimeSignatureSecrets) PersistentScalarsAndOffsets() (scalars OneTimeSignatureSecretsPersistent, offsets []KeyedSubkey) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.persistentScalarsLocked(), s.encodedOffsetsLocked()
}

// OneTimeSignatureSecretsFromParts reassembles OneTimeSignatureSecrets from
// scalars and subkey rows produced by PersistentParts (possibly trimmed by
// row deletions in storage).  Zero rows reassemble to nil slices, preserving
// the DeleteBeforeFineGrained semantics that an exhausted key's FirstBatch is
// never spuriously bumped.
func OneTimeSignatureSecretsFromParts(
	scalars OneTimeSignatureSecretsPersistent, batches []KeyedSubkey, offsets []KeyedSubkey,
) (*OneTimeSignatureSecrets, error) {
	if len(scalars.Batches) != 0 || len(scalars.Offsets) != 0 {
		return nil, fmt.Errorf("OneTimeSignatureSecretsFromParts: scalars carry %d batch and %d offset subkeys, expected none", len(scalars.Batches), len(scalars.Offsets))
	}

	if len(batches) > 0 {
		scalars.Batches = make([]ephemeralSubkey, len(batches))
		for i, row := range batches {
			if want := scalars.FirstBatch + uint64(i); row.Index != want {
				return nil, fmt.Errorf("OneTimeSignatureSecretsFromParts: batch row %d has index %d, expected %d", i, row.Index, want)
			}
			if err := protocol.Decode(row.Key, &scalars.Batches[i]); err != nil {
				return nil, fmt.Errorf("OneTimeSignatureSecretsFromParts: batch row %d (index %d) failed to decode: %w", i, row.Index, err)
			}
		}
	}

	if len(offsets) > 0 {
		scalars.Offsets = make([]ephemeralSubkey, len(offsets))
		for j, row := range offsets {
			if want := scalars.FirstOffset + uint64(j); row.Index != want {
				return nil, fmt.Errorf("OneTimeSignatureSecretsFromParts: offset row %d has index %d, expected %d", j, row.Index, want)
			}
			if err := protocol.Decode(row.Key, &scalars.Offsets[j]); err != nil {
				return nil, fmt.Errorf("OneTimeSignatureSecretsFromParts: offset row %d (index %d) failed to decode: %w", j, row.Index, err)
			}
		}
	}

	return &OneTimeSignatureSecrets{OneTimeSignatureSecretsPersistent: scalars}, nil
}
