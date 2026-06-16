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

package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

const (
	pqPrivateKeyMagic      = "ALGOKEY-PQ-PRIVATE"
	pqPublicKeyMagic       = "ALGOKEY-PQ-PUBLIC"
	pqMnemonicSchemeHeader = "Scheme:"
)

var (
	errPQKeyWrongType     = errors.New("pq key file has the wrong type")
	errPQKeyMalformed     = errors.New("pq key file is malformed")
	errPQKeyDerivation    = errors.New("pq key derivation input is malformed")
	errPQSaltNotCompliant = errors.New("pq address salt is not compliant")
)

type pqPublicMaterial struct {
	scheme protocol.PQScheme
	salt   basics.PQAddressSalt
	pk     []byte
	addr   basics.Address
}

type pqSigningMaterial struct {
	public  pqPublicMaterial
	private []byte
}

type pqRootMaterial struct {
	scheme  protocol.PQScheme
	entropy crypto.Seed
	public  pqPublicMaterial
}

type pqPrivateKeyPayload struct {
	Scheme  protocol.PQScheme `codec:"scheme"`
	Entropy []byte            `codec:"entropy"`
}

type pqPublicKeyPayload struct {
	Scheme    protocol.PQScheme    `codec:"scheme"`
	Salt      basics.PQAddressSalt `codec:"salt"`
	PublicKey []byte               `codec:"public-key"`
}

func writePQRootKeyFile(filename string, root pqRootMaterial) error {
	data := encodePQPrivateKeyFileBytes(root)
	defer zeroBytes(data)
	if err := writeNewFile(filename, data, 0600); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", filename, err)
	}
	return nil
}

func writePQPublicKeyFile(filename string, public pqPublicMaterial) error {
	data := encodePQPublicKeyFileBytes(public)
	if err := writeNewFile(filename, data, 0666); err != nil {
		return fmt.Errorf("cannot write public key to %s: %w", filename, err)
	}
	return nil
}

func readPQRootKeyFile(filename string) (pqRootMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqRootMaterial{}, fmt.Errorf("cannot read private key from %s: %w", filename, err)
	}
	defer zeroBytes(data)

	root, err := decodePQPrivateKeyFileBytes(data)
	if err != nil {
		return pqRootMaterial{}, err
	}
	return root, nil
}

func readPQSigningMaterial(filename string) (pqSigningMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqSigningMaterial{}, fmt.Errorf("cannot read private key from %s: %w", filename, err)
	}
	defer zeroBytes(data)

	scheme, entropy, err := decodePQPrivateKeyEntropy(data)
	if err != nil {
		return pqSigningMaterial{}, err
	}
	defer zeroBytes(entropy[:])

	return derivePQSigningMaterialFromEntropy(scheme, entropy[:])
}

func readPQPublicKeyFile(filename string) (pqPublicMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqPublicMaterial{}, fmt.Errorf("cannot read public key from %s: %w", filename, err)
	}
	return decodePQPublicKeyFileBytes(data)
}

func encodePQPrivateKeyFileBytes(root pqRootMaterial) []byte {
	entropy := slices.Clone(root.entropy[:])
	defer zeroBytes(entropy)
	payload := pqPrivateKeyPayload{
		Scheme:  root.scheme,
		Entropy: entropy,
	}
	return encodePQPayload(pqPrivateKeyMagic, payload)
}

func encodePQPublicKeyFileBytes(public pqPublicMaterial) []byte {
	payload := pqPublicKeyPayload{
		Scheme:    public.scheme,
		Salt:      public.salt,
		PublicKey: slices.Clone(public.pk),
	}
	return encodePQPayload(pqPublicKeyMagic, payload)
}

func encodePQPayload(magic string, payload interface{}) []byte {
	encoded := protocol.EncodeReflect(payload)
	defer zeroBytes(encoded)
	out := make([]byte, 0, len(magic)+1+len(encoded))
	out = append(out, magic...)
	out = append(out, '\n')
	out = append(out, encoded...)
	return out
}

// decodePQPrivateKeyEntropy parses the stored {scheme, entropy} from a private
// key file without deriving the (expensive) key material.
func decodePQPrivateKeyEntropy(data []byte) (protocol.PQScheme, crypto.Seed, error) {
	var payload pqPrivateKeyPayload
	if err := decodePQPayload(data, pqPrivateKeyMagic, &payload); err != nil {
		zeroBytes(payload.Entropy)
		return "", crypto.Seed{}, err
	}
	defer zeroBytes(payload.Entropy)
	if len(payload.Entropy) != pqKeyEntropySize {
		return "", crypto.Seed{}, fmt.Errorf("%w: got entropy size %d, want %d", errPQKeyMalformed, len(payload.Entropy), pqKeyEntropySize)
	}
	var entropy crypto.Seed
	copy(entropy[:], payload.Entropy)
	return payload.Scheme, entropy, nil
}

func decodePQPrivateKeyFileBytes(data []byte) (pqRootMaterial, error) {
	scheme, entropy, err := decodePQPrivateKeyEntropy(data)
	if err != nil {
		return pqRootMaterial{}, err
	}
	defer zeroBytes(entropy[:])
	return rootMaterialFromEntropy(scheme, entropy)
}

func decodePQPublicKeyFileBytes(data []byte) (pqPublicMaterial, error) {
	var payload pqPublicKeyPayload
	if err := decodePQPayload(data, pqPublicKeyMagic, &payload); err != nil {
		return pqPublicMaterial{}, err
	}
	public, err := publicMaterialFromFields(payload.Scheme, payload.Salt, payload.PublicKey)
	if err != nil {
		return pqPublicMaterial{}, err
	}
	if !public.addr.IsPQCompliant() {
		return pqPublicMaterial{}, fmt.Errorf("%w: public key file address %s", errPQSaltNotCompliant, public.addr)
	}
	return public, nil
}

func decodePQPayload(data []byte, magic string, payload interface{}) error {
	prefix := []byte(magic + "\n")
	if !bytes.HasPrefix(data, prefix) {
		return fmt.Errorf("%w: missing %s magic", errPQKeyWrongType, magic)
	}
	if len(data) == len(prefix) {
		return errPQKeyMalformed
	}
	if err := protocol.DecodeReflect(data[len(prefix):], payload); err != nil {
		return fmt.Errorf("%w: %w", errPQKeyMalformed, err)
	}
	return nil
}

func canonicalPublicMaterialFromKey(scheme protocol.PQScheme, publicKey []byte) (pqPublicMaterial, error) {
	salt, _, err := basics.CanonicalPQAddressSalt(scheme, publicKey)
	if err != nil {
		return pqPublicMaterial{}, err
	}
	public, err := publicMaterialFromFields(scheme, salt, publicKey)
	if err != nil {
		return pqPublicMaterial{}, err
	}
	if !public.addr.IsPQCompliant() {
		return pqPublicMaterial{}, fmt.Errorf("%w: canonical address %s", errPQSaltNotCompliant, public.addr)
	}
	return public, nil
}

func publicMaterialFromFields(scheme protocol.PQScheme, salt basics.PQAddressSalt, publicKey []byte) (pqPublicMaterial, error) {
	spec, err := lookupPQScheme(scheme)
	if err != nil {
		return pqPublicMaterial{}, err
	}
	if uint64(len(publicKey)) != spec.PublicKeySize {
		return pqPublicMaterial{}, fmt.Errorf("%w: got public key size %d, want %d", errPQKeyMalformed, len(publicKey), spec.PublicKeySize)
	}
	if err = spec.ValidatePublicKey(publicKey); err != nil {
		return pqPublicMaterial{}, err
	}

	addr := basics.PQAddress(scheme, salt, publicKey)
	return pqPublicMaterial{
		scheme: scheme,
		salt:   salt,
		pk:     slices.Clone(publicKey),
		addr:   addr,
	}, nil
}

// resolvePQSalt resolves saltValue ("canonical", or a decimal in 0..255) to a
// public material for the same scheme and public key. The canonical salt always
// derives a compliant address; for an explicit salt, callers decide how to treat
// non-compliant addresses via public.addr.IsPQCompliant().
func resolvePQSalt(public pqPublicMaterial, saltValue string) (pqPublicMaterial, error) {
	if saltValue == "" || strings.EqualFold(saltValue, "canonical") {
		return canonicalPublicMaterialFromKey(public.scheme, public.pk)
	}

	n, err := strconv.ParseUint(saltValue, 10, 8)
	if err != nil {
		return pqPublicMaterial{}, fmt.Errorf("invalid pq salt %q: use canonical or 0..255", saltValue)
	}
	salt := basics.PQAddressSalt(n)
	return publicMaterialFromFields(public.scheme, salt, public.pk)
}

// writePQMnemonicFile writes a self-describing mnemonic file: a "Scheme: <tag>"
// header line followed by the 25-word phrase encoding the root entropy.
func writePQMnemonicFile(filename string, scheme protocol.PQScheme, entropy crypto.Seed) error {
	mnemonic, err := mnemonicFromSeed(entropy)
	if err != nil {
		return err
	}
	data := []byte(fmt.Sprintf("%s %s\n%s\n", pqMnemonicSchemeHeader, scheme, mnemonic))
	defer zeroBytes(data)
	return writeNewFile(filename, data, 0600)
}

// readPQMnemonicFile reads a file written by writePQMnemonicFile and returns the
// recorded scheme and the entropy recovered from the phrase.
func readPQMnemonicFile(filename string) (protocol.PQScheme, crypto.Seed, error) {
	if filename == stdinFileNameValue {
		return "", crypto.Seed{}, fmt.Errorf("refusing to read mnemonic from stdin")
	}
	data, err := readFile(filename)
	if err != nil {
		return "", crypto.Seed{}, err
	}
	defer zeroBytes(data)

	header, mnemonic, ok := bytes.Cut(data, []byte{'\n'})
	if !ok {
		return "", crypto.Seed{}, fmt.Errorf("%w: missing %q header", errPQKeyMalformed, pqMnemonicSchemeHeader)
	}
	tag, ok := bytes.CutPrefix(bytes.TrimSpace(header), []byte(pqMnemonicSchemeHeader))
	if !ok {
		return "", crypto.Seed{}, fmt.Errorf("%w: missing %q header", errPQKeyMalformed, pqMnemonicSchemeHeader)
	}

	// seedFromMnemonic/MnemonicToKey take a string, so the phrase is unavoidably
	// copied into an immutable (unwipeable) string; keep that copy to the words
	// alone rather than the whole file, which stays a wiped []byte.
	seed, err := seedFromMnemonic(string(bytes.TrimSpace(mnemonic)))
	if err != nil {
		return "", crypto.Seed{}, err
	}
	return protocol.PQScheme(string(bytes.TrimSpace(tag))), seed, nil
}

func isPQKeyMaterial(data []byte) bool {
	return bytes.HasPrefix(data, []byte(pqPrivateKeyMagic+"\n")) ||
		bytes.HasPrefix(data, []byte(pqPublicKeyMagic+"\n"))
}

func wipePQSigningMaterial(signing *pqSigningMaterial) {
	zeroBytes(signing.private)
	signing.private = nil
}

func wipePQRootMaterial(root *pqRootMaterial) {
	zeroBytes(root.entropy[:])
}
