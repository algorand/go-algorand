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

// Row-oriented persistent storage of OneTimeSignatureSecrets: one row per
// ephemeral subkey plus a header that records the fixed fields and the row
// counts, so the header alone determines the expected rows and the per-round
// deletion of a used subkey is a row delete rather than a whole-keyset
// rewrite.
//
// The helpers operate on a Snapshot() and take no locks.  A snapshot shares
// the subkey backing arrays with the live secrets, which is safe because
// DeleteBefore* only reslices them or allocates new ones, never modifying
// subkeys in place; wiping consumed subkeys in memory would require copying
// in Snapshot.

//msgp:ignore KeyedSubkey

// KeyedSubkey is one ephemeral subkey prepared for row-oriented storage.
// Index is the absolute batch number for batch subkeys, or the absolute
// offset (within batch FirstBatch-1) for offset subkeys.  Key is the msgpack
// encoding of the subkey.
type KeyedSubkey struct {
	Index uint64
	Key   []byte
}

// OneTimeSignatureSecretsHeader is the stored description of a row-oriented
// OneTimeSignatureSecrets: the fixed-size fields plus the number of subkey
// rows.  Batch subkey rows cover [FirstBatch, FirstBatch+BatchCount); offset
// subkey rows cover [FirstOffset, FirstOffset+OffsetCount) and belong to
// batch FirstBatch-1.  Both counts zero means the key is exhausted.
type OneTimeSignatureSecretsHeader struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Verifier OneTimeSignatureVerifier `codec:"pk"`

	FirstBatch uint64 `codec:"fb"`
	BatchCount uint64 `codec:"nb"`

	FirstOffset uint64 `codec:"fo"`
	OffsetCount uint64 `codec:"no"`

	// OffsetsPK2 is the intermediate-level public key that verifies the
	// offset subkeys, and OffsetsPK2Sig is the master key's signature on
	// OneTimeSignatureSubkeyBatchID(OffsetsPK2, FirstBatch-1).
	OffsetsPK2    ed25519PublicKey `codec:"pk2"`
	OffsetsPK2Sig ed25519Signature `codec:"pk2sig"`
}

// Exhausted reports whether the header describes a key with no subkeys left.
func (h OneTimeSignatureSecretsHeader) Exhausted() bool {
	return h.BatchCount == 0 && h.OffsetCount == 0
}

// Header returns the storage header describing a snapshot.
func (s OneTimeSignatureSecretsPersistent) Header() OneTimeSignatureSecretsHeader {
	return OneTimeSignatureSecretsHeader{
		Verifier:      s.OneTimeSignatureVerifier,
		FirstBatch:    s.FirstBatch,
		BatchCount:    uint64(len(s.Batches)),
		FirstOffset:   s.FirstOffset,
		OffsetCount:   uint64(len(s.Offsets)),
		OffsetsPK2:    s.OffsetsPK2,
		OffsetsPK2Sig: s.OffsetsPK2Sig,
	}
}

// EncodedBatches returns the batch subkeys of a snapshot as rows;
// rows[i].Index == FirstBatch+i.
func (s OneTimeSignatureSecretsPersistent) EncodedBatches() []KeyedSubkey {
	return encodeSubkeys(s.FirstBatch, s.Batches)
}

// EncodedOffsets returns the offset subkeys of a snapshot as rows;
// rows[j].Index == FirstOffset+j, all belonging to batch FirstBatch-1.
func (s OneTimeSignatureSecretsPersistent) EncodedOffsets() []KeyedSubkey {
	return encodeSubkeys(s.FirstOffset, s.Offsets)
}

func encodeSubkeys(first uint64, keys []ephemeralSubkey) []KeyedSubkey {
	if len(keys) == 0 {
		return nil
	}
	rows := make([]KeyedSubkey, len(keys))
	for i := range keys {
		rows[i] = KeyedSubkey{Index: first + uint64(i), Key: protocol.Encode(&keys[i])}
	}
	return rows
}

// decodeSubkeys is the inverse of encodeSubkeys: rows must be contiguous from
// first.  Zero rows decode to a nil slice.
func decodeSubkeys(what string, first uint64, rows []KeyedSubkey) ([]ephemeralSubkey, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	keys := make([]ephemeralSubkey, len(rows))
	for i, row := range rows {
		if want := first + uint64(i); row.Index != want {
			return nil, fmt.Errorf("OneTimeSignatureSecretsFromRows: %s row %d has index %d, expected %d", what, i, row.Index, want)
		}
		if err := protocol.Decode(row.Key, &keys[i]); err != nil {
			return nil, fmt.Errorf("OneTimeSignatureSecretsFromRows: %s row %d (index %d) failed to decode: %w", what, i, row.Index, err)
		}
	}
	return keys, nil
}

// OneTimeSignatureSecretsFromRows reassembles OneTimeSignatureSecrets from a
// header and the subkey rows it describes, in index order.  Zero counts
// reassemble to nil slices, preserving the DeleteBeforeFineGrained semantics
// that an exhausted key's FirstBatch is never spuriously bumped.
func OneTimeSignatureSecretsFromRows(hdr OneTimeSignatureSecretsHeader, batches []KeyedSubkey, offsets []KeyedSubkey) (*OneTimeSignatureSecrets, error) {
	if uint64(len(batches)) != hdr.BatchCount {
		return nil, fmt.Errorf("OneTimeSignatureSecretsFromRows: %d batch subkey rows, header expects %d: missing or extra rows", len(batches), hdr.BatchCount)
	}
	if uint64(len(offsets)) != hdr.OffsetCount {
		return nil, fmt.Errorf("OneTimeSignatureSecretsFromRows: %d offset subkey rows, header expects %d: missing or extra rows", len(offsets), hdr.OffsetCount)
	}
	if hdr.OffsetCount > 0 && hdr.FirstBatch == 0 {
		return nil, fmt.Errorf("OneTimeSignatureSecretsFromRows: offset subkeys present but no batch has been expanded (FirstBatch is 0)")
	}

	p := OneTimeSignatureSecretsPersistent{
		OneTimeSignatureVerifier: hdr.Verifier,
		FirstBatch:               hdr.FirstBatch,
		FirstOffset:              hdr.FirstOffset,
		OffsetsPK2:               hdr.OffsetsPK2,
		OffsetsPK2Sig:            hdr.OffsetsPK2Sig,
	}
	var err error
	if p.Batches, err = decodeSubkeys("batch", hdr.FirstBatch, batches); err != nil {
		return nil, err
	}
	if p.Offsets, err = decodeSubkeys("offset", hdr.FirstOffset, offsets); err != nil {
		return nil, err
	}
	return &OneTimeSignatureSecrets{OneTimeSignatureSecretsPersistent: p}, nil
}
