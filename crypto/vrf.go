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


// deprecated names + wrappers -- TODO remove

// VRFVerifier is a deprecated name for VrfPubkey
type VRFVerifier = VrfPubkey

// VRFProof is a deprecated name for VrfProof
type VRFProof = VrfProof

// VRFSecrets is a wrapper for a VRF keypair. Use *VrfPrivkey instead
type VRFSecrets struct {
	_struct struct{} `codec:""`

	PK VrfPubkey
	SK VrfPrivkey
}

// GenerateVRFSecrets is deprecated, use VrfKeygen or VrfKeygenFromSeed instead
func GenerateVRFSecrets() *VRFSecrets {
	s := new(VRFSecrets)
	s.PK, s.SK = VrfKeygen()
	return s
}

// TODO: Go arrays are copied by value, so any call to e.g. VrfPrivkey.Prove() makes a copy of the secret key that lingers in memory.
// To avoid this, should we instead allocate memory for secret keys here (maybe even in the C heap) and pass around pointers?
// e.g., allocate a privkey with sodium_malloc and have VrfPrivkey be of type unsafe.Pointer?
type (
	// A VrfPrivkey is a private key used for producing VRF proofs.
	// Specifically, we use a 64-byte ed25519 private key (the latter 32-bytes are the precomputed public key)
	VrfPrivkey [64]byte
	// A VrfPubkey is a public key that can be used to verify VRF proofs.
	VrfPubkey [32]byte
	// A VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
	// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
	VrfProof [80]byte
	// VrfOutput is a 64-byte pseudorandom value that can be computed from a VrfProof.
	// The VRF scheme guarantees that such output will be unique
	VrfOutput [64]byte
)

// Prove constructs a VRF Proof for a given Hashable.
// ok will be false if the private key is malformed.
func (sk VrfPrivkey) Prove(message Hashable) (proof VrfProof, ok bool) {
	return sk.proveBytes(HashRep(message))
}

// Verify checks a VRF proof of a given Hashable. If the proof is valid the pseudorandom VrfOutput will be returned.
// For a given public key and message, there are potentially multiple valid proofs.
// However, given a public key and message, all valid proofs will yield the same output.
// Moreover, the output is indistinguishable from random to anyone without the proof or the secret key.
func (pk VrfPubkey) Verify(p VrfProof, message Hashable) (bool, VrfOutput) {
	return pk.verifyBytes(p, HashRep(message))
}
