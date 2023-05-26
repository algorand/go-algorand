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
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"
)

// A OneTimeSignature is a cryptographic signature that is produced a limited
// number of times and provides forward integrity.
//
// Specifically, a OneTimeSignature is generated from an ephemeral secret. After
// some number of messages is signed under a given OneTimeSignatureIdentifier
// identifier, the corresponding secret is deleted. This prevents the
// secret-holder from signing a contradictory message in the future in the event
// of a secret-key compromise.
type OneTimeSignature struct {
	// Unfortunately we forgot to mark this struct as omitempty at
	// one point, and now it's hard to recover from that if we want
	// to preserve encodings..
	_struct struct{} `codec:""`

	// Sig is a signature of msg under the key PK.
	Sig ed25519Signature `codec:"s"`
	PK  ed25519PublicKey `codec:"p"`

	// Old-style signature that does not use proper domain separation.
	// PKSigOld is unused; however, unfortunately we forgot to mark it
	// `codec:omitempty` and so it appears (with zero value) in certs.
	// This means we can't delete the field without breaking catchup.
	PKSigOld ed25519Signature `codec:"ps"`

	// Used to verify a new-style two-level ephemeral signature.
	// PK1Sig is a signature of OneTimeSignatureSubkeyOffsetID(PK, Batch, Offset) under the key PK2.
	// PK2Sig is a signature of OneTimeSignatureSubkeyBatchID(PK2, Batch) under the master key (OneTimeSignatureVerifier).
	PK2    ed25519PublicKey `codec:"p2"`
	PK1Sig ed25519Signature `codec:"p1s"`
	PK2Sig ed25519Signature `codec:"p2s"`
}

// A OneTimeSignatureSubkeyBatchID identifies an ephemeralSubkey of a batch
// for the purposes of signing it with the top-level master key.
type OneTimeSignatureSubkeyBatchID struct {
	// Unfortunately we forgot to mark this struct as omitempty at
	// one point, and now it's hard to recover from that if we want
	// to preserve encodings..
	_struct struct{} `codec:""`

	SubKeyPK ed25519PublicKey `codec:"pk"`
	Batch    uint64           `codec:"batch"`
}

// ToBeHashed implements the Hashable interface for a OneTimeSignatureSubkeyBatchID.
// This is used to sign an intermediate subkey for a batch, in the new style
// (contrast with OneTimeSignatureIdentifier.BatchBytes).
func (batch OneTimeSignatureSubkeyBatchID) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.OneTimeSigKey1, protocol.Encode(&batch)
}

// A OneTimeSignatureSubkeyOffsetID identifies an ephemeralSubkey of a specific
// offset within a batch, for the purposes of signing it with the batch subkey.
type OneTimeSignatureSubkeyOffsetID struct {
	// Unfortunately we forgot to mark this struct as omitempty at
	// one point, and now it's hard to recover from that if we want
	// to preserve encodings..
	_struct struct{} `codec:""`

	SubKeyPK ed25519PublicKey `codec:"pk"`
	Batch    uint64           `codec:"batch"`
	Offset   uint64           `codec:"off"`
}

// ToBeHashed implements the Hashable interface for a OneTimeSignatureSubkeyOffsetID.
// This is used to sign a subkey for a specific offset in a batch.
func (off OneTimeSignatureSubkeyOffsetID) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.OneTimeSigKey2, protocol.Encode(&off)
}

// A OneTimeSignatureIdentifier is an identifier under which a OneTimeSignature is
// produced on a given message.  This identifier is represented using a two-level
// structure, which corresponds to two levels of our ephemeral key tree.
type OneTimeSignatureIdentifier struct {
	// Batch represents the most-significant part of the identifier.
	Batch uint64

	// Offset represents the least-significant part of the identifier.
	// When moving to a new Batch, the Offset values restart from 0.
	Offset uint64
}

// BatchBytes converts a OneTimeSignatureIdentifier into a byte slice representing
// the 64-bit batch number.  This is used for the old-style way of signing an
// ephemeral subkey identifier.
func (id OneTimeSignatureIdentifier) BatchBytes() []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, id.Batch)
	return data
}

// A OneTimeSignatureVerifier is used to identify the holder of
// OneTimeSignatureSecrets and prove the authenticity of OneTimeSignatures
// against some OneTimeSignatureIdentifier.
type OneTimeSignatureVerifier ed25519PublicKey

// OneTimeSignatureSecrets are used to produced unforgeable signatures over a
// message.
//
// When the method OneTimeSignatureSecrets.DeleteBefore(ID) is called, ephemeral
// secrets corresponding to OneTimeSignatureIdentifiers preceding ID are
// deleted. Thereafter, an entity can no longer sign different messages with old
// OneTimeSignatureIdentifiers, protecting the integrity of the messages signed
// under those identifiers.
type OneTimeSignatureSecrets struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	OneTimeSignatureSecretsPersistent

	// We keep track of an RNG, used to generate additional randomness.
	// This is used purely for testing (fuzzing, specifically).  Except
	// for testing, the RNG is SystemRNG.
	rng RNG

	// We use a read-write lock to guard against concurrent invocations,
	// such as Sign() concurrently running with DeleteBefore*().
	mu deadlock.RWMutex
}

// OneTimeSignatureSecretsPersistent denotes the fields of a OneTimeSignatureSecrets
// that get stored to persistent storage (through reflection on exported fields).
type OneTimeSignatureSecretsPersistent struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	OneTimeSignatureVerifier

	// FirstBatch denotes the first batch whose subkey appears in Batches.
	// The odd `codec:` name is for backwards compatibility with previous
	// stored keys where we failed to give any explicit `codec:` name.
	FirstBatch uint64            `codec:"First"`
	Batches    []ephemeralSubkey `codec:"Sub,allocbound=-"`

	// FirstOffset denotes the first offset whose subkey appears in Offsets.
	// These subkeys correspond to batch FirstBatch-1.
	FirstOffset uint64            `codec:"firstoff"`
	Offsets     []ephemeralSubkey `codec:"offkeys,allocbound=-"` // the bound is keyDilution

	// When Offsets is non-empty, OffsetsPK2 is the intermediate-level public
	// key that can be used to verify signatures on the subkeys in Offsets, and
	// OffsetsPK2Sig is the signature from the master key (OneTimeSignatureVerifier)
	// on OneTimeSignatureSubkeyBatchID(OffsetsPK2, FirstBatch-1).
	OffsetsPK2    ed25519PublicKey `codec:"offpk2"`
	OffsetsPK2Sig ed25519Signature `codec:"offpk2sig"`
}

// An ephemeralSubkey produces OneTimeSignatures for messages and is deleted
// after use.
type ephemeralSubkey struct {
	// Unfortunately we forgot to mark this struct as omitempty at
	// one point, and now it's hard to recover from that if we want
	// to preserve encodings..
	_struct struct{} `codec:""`

	PK ed25519PublicKey
	SK ed25519PrivateKey

	// PKSigOld is the signature that authenticates PK.  It is the
	// signature of the PK together with the batch number, using an
	// old style of signatures that we support for backwards
	// compatibility (thus the odd `codec:` name).
	PKSigOld ed25519Signature `codec:"PKSig"`

	// PKSigNew is the signature that authenticates PK, signed using the
	// Hashable interface for domain separation (the Hashable object is either
	// OneTimeSignatureSubkeyBatchID or OneTimeSignatureSubkeyOffsetID).
	PKSigNew ed25519Signature `codec:"sig2"`
}

// GenerateOneTimeSignatureSecretsRNG creates a limited number of secrets
// that sign messages under OneTimeSignatureIdentifiers in the range
// [startBatch, startBatch+numBatches).
//
// This range includes startBatch and excludes startBatch+numBatches.
//
// Randomness comes from the supplied RNG.
func GenerateOneTimeSignatureSecretsRNG(startBatch uint64, numBatches uint64, rng RNG) *OneTimeSignatureSecrets {
	s := new(OneTimeSignatureSecrets)

	master, ephemeralSec := ed25519GenerateKeyRNG(rng)

	subkeys := make([]ephemeralSubkey, numBatches)
	for i := uint64(0); i < numBatches; i++ {
		pk, sk := ed25519GenerateKeyRNG(rng)
		batchnum := startBatch + i

		newid := OneTimeSignatureSubkeyBatchID{SubKeyPK: pk, Batch: batchnum}
		newsig := ed25519Sign(ephemeralSec, HashRep(newid))

		subkeys[i] = ephemeralSubkey{
			PK:       pk,
			SK:       sk,
			PKSigNew: newsig,
		}
	}

	s.OneTimeSignatureVerifier = OneTimeSignatureVerifier(master)
	s.FirstBatch = startBatch
	s.Batches = subkeys
	s.rng = rng
	return s
}

// GenerateOneTimeSignatureSecrets is a version of GenerateOneTimeSignatureSecretsRNG
// that uses the system-wide randomness source.
func GenerateOneTimeSignatureSecrets(startBatch uint64, numBatches uint64) *OneTimeSignatureSecrets {
	return GenerateOneTimeSignatureSecretsRNG(startBatch, numBatches, SystemRNG)
}

// getRNG returns the RNG for OneTimeSignatureSecrets.
// If we serialized and de-serialized the OneTimeSignatureSecrets,
// the private rng field might be nil.  Since rng is used only
// for testing, in this case we return SystemRNG.
func (s *OneTimeSignatureSecrets) getRNG() RNG {
	if s.rng != nil {
		return s.rng
	}
	return SystemRNG
}

// Sign produces a OneTimeSignature of some Hashable message under some
// OneTimeSignatureIdentifier.
func (s *OneTimeSignatureSecrets) Sign(id OneTimeSignatureIdentifier, message Hashable) OneTimeSignature {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if we already have a partial batch of subkeys.
	if id.Batch+1 == s.FirstBatch && id.Offset >= s.FirstOffset && id.Offset-s.FirstOffset < uint64(len(s.Offsets)) {
		offidx := id.Offset - s.FirstOffset
		sig := ed25519Sign(s.Offsets[offidx].SK, HashRep(message))
		return OneTimeSignature{
			Sig:    sig,
			PK:     s.Offsets[offidx].PK,
			PK1Sig: s.Offsets[offidx].PKSigNew,
			PK2:    s.OffsetsPK2,
			PK2Sig: s.OffsetsPK2Sig,
		}
	}

	// Check if we are asking for an offset from an available batch.
	if id.Batch >= s.FirstBatch && id.Batch-s.FirstBatch < uint64(len(s.Batches)) {
		// Since we have not yet broken out this batch into per-offset keys,
		// generate a fresh subkey right away, sign it, and use it.
		pk, sk := ed25519GenerateKeyRNG(s.getRNG())
		sig := ed25519Sign(sk, HashRep(message))

		batchidx := id.Batch - s.FirstBatch
		pksig := s.Batches[batchidx].PKSigNew

		pk1id := OneTimeSignatureSubkeyOffsetID{
			SubKeyPK: pk,
			Batch:    id.Batch,
			Offset:   id.Offset,
		}
		return OneTimeSignature{
			Sig:    sig,
			PK:     pk,
			PK1Sig: ed25519Sign(s.Batches[batchidx].SK, HashRep(pk1id)),
			PK2:    s.Batches[batchidx].PK,
			PK2Sig: pksig,
		}
	}

	errmsg := fmt.Sprintf("tried to sign %v with out-of-range one-time identifier %v (firstbatch %d, len(batches) %d, firstoffset %d, len(offsets) %d)",
		message, id, s.FirstBatch, len(s.Batches), s.FirstOffset, len(s.Offsets))

	// It's expected that we sometimes hit this error, when trying to sign
	// using an identifier of a block that we just reached agreement on and
	// thus deleted.  Don't warn if we're out-of-range by just one.  This
	// might still trigger a false warning if we're out-of-range by just one
	// and it happens to be a batch boundary, but we don't have the batch
	// size (key dilution) parameter accessible here easily.
	if s.FirstBatch == id.Batch+1 && s.FirstOffset == id.Offset+1 {
		logging.Base().Info(errmsg)
	} else {
		logging.Base().Warn(errmsg)
	}
	return OneTimeSignature{}
}

// Verify verifies that some Hashable signature was signed under some
// OneTimeSignatureVerifier and some OneTimeSignatureIdentifier.
//
// It returns true if this is the case; otherwise, it returns false.
func (v OneTimeSignatureVerifier) Verify(id OneTimeSignatureIdentifier, message Hashable, sig OneTimeSignature) bool {
	offsetID := OneTimeSignatureSubkeyOffsetID{
		SubKeyPK: sig.PK,
		Batch:    id.Batch,
		Offset:   id.Offset,
	}
	batchID := OneTimeSignatureSubkeyBatchID{
		SubKeyPK: sig.PK2,
		Batch:    id.Batch,
	}

	allValid, _ := batchVerificationImpl(
		[][]byte{HashRep(batchID), HashRep(offsetID), HashRep(message)},
		[]PublicKey{PublicKey(v), PublicKey(batchID.SubKeyPK), PublicKey(offsetID.SubKeyPK)},
		[]Signature{Signature(sig.PK2Sig), Signature(sig.PK1Sig), Signature(sig.Sig)},
	)
	return allValid
}

// DeleteBeforeFineGrained deletes ephemeral keys before (but not including) the given id.
func (s *OneTimeSignatureSecrets) DeleteBeforeFineGrained(current OneTimeSignatureIdentifier, numKeysPerBatch uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// TODO: Securely wipe the keys from memory.

	// If we are just advancing in the same batch, simply delete some offset
	// subkeys.
	if current.Batch+1 == s.FirstBatch {
		if current.Offset > s.FirstOffset {
			jump := current.Offset - s.FirstOffset
			if jump > uint64(len(s.Offsets)) {
				jump = uint64(len(s.Offsets))
			}

			s.FirstOffset += jump
			s.Offsets = s.Offsets[jump:]
		}

		return
	}

	// If we are trying to forget something earlier, there's nothing to do.
	if current.Batch+1 < s.FirstBatch {
		return
	}

	// We are trying to move forward into a new batch.  The plan is fourfold:
	// 1. Delete existing offsets.
	s.Offsets = nil

	// 2. Delete any whole batches that we are jumping over.
	jump := current.Batch - s.FirstBatch
	if jump > uint64(len(s.Batches)) {
		// We ran out of whole batches.  Clear out everything.
		// If there weren't any batches to begin with, don't
		// bother bumping FirstBatch, so that we don't make
		// irrelevant changes to expired keys.
		if s.Batches != nil {
			s.FirstBatch = current.Batch
			s.Batches = nil
		}
		return
	}
	s.FirstBatch += jump
	s.Batches = s.Batches[jump:]

	// 3. Expand the next batch into offset subkeys.
	if len(s.Batches) == 0 {
		// We ran out of whole batches.
		return
	}

	s.OffsetsPK2 = s.Batches[0].PK
	s.OffsetsPK2Sig = s.Batches[0].PKSigNew

	s.FirstOffset = current.Offset
	for off := current.Offset; off < numKeysPerBatch; off++ {
		pk, sk := ed25519GenerateKeyRNG(s.getRNG())
		pksig := ed25519Sign(s.Batches[0].SK, HashRep(OneTimeSignatureSubkeyOffsetID{
			SubKeyPK: pk,
			Batch:    current.Batch,
			Offset:   off,
		}))
		s.Offsets = append(s.Offsets, ephemeralSubkey{
			PK:       pk,
			SK:       sk,
			PKSigNew: pksig,
		})
	}

	// 4. Delete the next batch subkey that we just expanded.
	s.FirstBatch++
	s.Batches = s.Batches[1:]
}

// Snapshot returns a copy of OneTimeSignatureSecrets consistent with
// respect to concurrent mutating calls (specifically, DeleteBefore*).
// This snapshot can be used for serializing the OneTimeSignatureSecrets
// to persistent storage.
func (s *OneTimeSignatureSecrets) Snapshot() OneTimeSignatureSecrets {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return OneTimeSignatureSecrets{
		OneTimeSignatureSecretsPersistent: s.OneTimeSignatureSecretsPersistent,
	}
}

// OneTimeSigner is a wrapper for OneTimeSignatureSecrets that also
// includes the appropriate KeyDilution value.  If zero, the value
// should be inherited from ConsensusParams.DefaultKeyDilution.
type OneTimeSigner struct {
	*OneTimeSignatureSecrets
	OptionalKeyDilution uint64
}

// KeyDilution returns the appropriate key dilution value for a OneTimeSigner.
func (ots OneTimeSigner) KeyDilution(defaultKeyDilution uint64) uint64 {
	if ots.OptionalKeyDilution != 0 {
		return ots.OptionalKeyDilution
	}

	return defaultKeyDilution
}
