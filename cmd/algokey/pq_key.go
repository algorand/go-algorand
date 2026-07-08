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
	"os"
	"strconv"
	"strings"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

const (
	pqPrivateKeyMagic      = "ALGO-PQ-PRIVATE"
	pqPublicKeyMagic       = "ALGO-PQ-PUBLIC"
	pqMnemonicSchemeHeader = "Scheme:"
)

var (
	errPQKeyWrongType     = errors.New("pq key file has the wrong type")
	errPQKeyMalformed     = errors.New("pq key file is malformed")
	errPQSaltNotCompliant = errors.New("pq address salt is not compliant")
)

// pqPublicMaterial is a PQ public key with its address salt. It is also the
// msgp payload stored after the PQ public-key magic prefix.
type pqPublicMaterial struct {
	_struct struct{} `codec:""`

	Scheme    protocol.PQScheme    `codec:"scheme"`
	Salt      basics.PQAddressSalt `codec:"salt"`
	PublicKey []byte               `codec:"public-key,allocbound=crypto.MaxPQPublicKeySize"`
}

func (m pqPublicMaterial) address() basics.Address {
	return basics.PQAddress(m.Scheme, m.Salt, m.PublicKey)
}

// pqPrivateKeyPayload is the msgp payload stored after the PQ private-key
// magic prefix.
type pqPrivateKeyPayload struct {
	_struct struct{} `codec:""`

	Scheme  protocol.PQScheme `codec:"scheme"`
	Entropy []byte            `codec:"entropy,allocbound=crypto.DigestSize"`
}

type pqSigningMaterial struct {
	public  pqPublicMaterial
	private []byte
}

type pqRootMaterial struct {
	entropy crypto.Seed
	public  pqPublicMaterial
}

func writePQRootKeyFile(filename string, root pqRootMaterial) error {
	data := encodePQPrivateKeyFileBytes(root)
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", filename, err)
	}
	return nil
}

func writePQPublicKeyFile(filename string, public pqPublicMaterial) error {
	data := encodePQPayload(pqPublicKeyMagic, &public)
	if err := os.WriteFile(filename, data, 0666); err != nil {
		return fmt.Errorf("cannot write public key to %s: %w", filename, err)
	}
	return nil
}

func readPQRootKeyFile(filename string) (pqRootMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqRootMaterial{}, fmt.Errorf("cannot read private key from %s: %w", filename, err)
	}
	return decodePQPrivateKeyFileBytes(data)
}

func readPQSigningMaterial(filename string) (pqSigningMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqSigningMaterial{}, fmt.Errorf("cannot read private key from %s: %w", filename, err)
	}

	scheme, entropy, err := decodePQPrivateKeyEntropy(data)
	if err != nil {
		return pqSigningMaterial{}, err
	}

	return derivePQSigningMaterialFromEntropy(scheme, entropy)
}

func readPQPublicKeyFile(filename string) (pqPublicMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqPublicMaterial{}, fmt.Errorf("cannot read public key from %s: %w", filename, err)
	}
	return decodePQPublicKeyFileBytes(data)
}

func encodePQPrivateKeyFileBytes(root pqRootMaterial) []byte {
	payload := pqPrivateKeyPayload{
		Scheme:  root.public.Scheme,
		Entropy: root.entropy[:],
	}
	return encodePQPayload(pqPrivateKeyMagic, &payload)
}

func encodePQPayload(magic string, payload msgp.Marshaler) []byte {
	return append([]byte(magic+"\n"), protocol.Encode(payload)...)
}

// decodePQPrivateKeyEntropy parses the stored {scheme, entropy} from a private
// key file without deriving the (expensive) key material.
func decodePQPrivateKeyEntropy(data []byte) (protocol.PQScheme, crypto.Seed, error) {
	var payload pqPrivateKeyPayload
	if err := decodePQPayload(data, pqPrivateKeyMagic, &payload); err != nil {
		return protocol.PQScheme{}, crypto.Seed{}, err
	}
	if len(payload.Entropy) != pqKeyEntropySize {
		return protocol.PQScheme{}, crypto.Seed{}, fmt.Errorf("%w: got entropy size %d, want %d", errPQKeyMalformed, len(payload.Entropy), pqKeyEntropySize)
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
	return rootMaterialFromEntropy(scheme, entropy)
}

func decodePQPublicKeyFileBytes(data []byte) (pqPublicMaterial, error) {
	var payload pqPublicMaterial
	if err := decodePQPayload(data, pqPublicKeyMagic, &payload); err != nil {
		return pqPublicMaterial{}, err
	}
	public, err := publicMaterialFromFields(payload.Scheme, payload.Salt, payload.PublicKey)
	if err != nil {
		return pqPublicMaterial{}, err
	}
	if !public.address().IsPQCompliant() {
		return pqPublicMaterial{}, fmt.Errorf("%w: public key file address %s", errPQSaltNotCompliant, public.address())
	}
	return public, nil
}

func decodePQPayload(data []byte, magic string, payload msgp.Unmarshaler) error {
	payloadBytes, ok := bytes.CutPrefix(data, []byte(magic+"\n"))
	if !ok {
		return fmt.Errorf("%w: missing %s magic", errPQKeyWrongType, magic)
	}
	if len(payloadBytes) == 0 {
		return errPQKeyMalformed
	}
	if err := protocol.Decode(payloadBytes, payload); err != nil {
		return fmt.Errorf("%w: %w", errPQKeyMalformed, err)
	}
	return nil
}

func canonicalPublicMaterialFromKey(scheme protocol.PQScheme, publicKey []byte) (pqPublicMaterial, error) {
	salt, _, err := basics.CanonicalPQAddressSalt(scheme, publicKey)
	if err != nil {
		return pqPublicMaterial{}, err
	}
	return publicMaterialFromFields(scheme, salt, publicKey)
}

func publicMaterialFromFields(scheme protocol.PQScheme, salt basics.PQAddressSalt, publicKey []byte) (pqPublicMaterial, error) {
	ops, ok := pqSchemeOpsByScheme[scheme]
	if !ok {
		return pqPublicMaterial{}, fmt.Errorf("%w: %q", crypto.ErrPQSchemeNotSupported, scheme)
	}
	if uint64(len(publicKey)) != ops.publicKeySize() {
		return pqPublicMaterial{}, fmt.Errorf("%w: got public key size %d, want %d", errPQKeyMalformed, len(publicKey), ops.publicKeySize())
	}

	return pqPublicMaterial{
		Scheme:    scheme,
		Salt:      salt,
		PublicKey: publicKey,
	}, nil
}

// resolvePQSalt resolves saltValue ("canonical", or a decimal in 0..255) to a
// public material for the same scheme and public key. The canonical salt always
// derives a compliant address; for an explicit salt, callers decide how to treat
// non-compliant addresses via public.addr.IsPQCompliant().
func resolvePQSalt(public pqPublicMaterial, saltValue string) (pqPublicMaterial, error) {
	if saltValue == "" || strings.EqualFold(saltValue, "canonical") {
		return canonicalPublicMaterialFromKey(public.Scheme, public.PublicKey)
	}

	n, err := strconv.ParseUint(saltValue, 10, 8)
	if err != nil {
		return pqPublicMaterial{}, fmt.Errorf("invalid pq salt %q: use canonical or 0..255", saltValue)
	}
	return publicMaterialFromFields(public.Scheme, basics.PQAddressSalt(n), public.PublicKey)
}

func writePQMnemonicFile(filename string, scheme protocol.PQScheme, entropy crypto.Seed) error {
	mnemonic, err := mnemonicFromSeed(entropy)
	if err != nil {
		return err
	}
	data := []byte(fmt.Sprintf("%s %s\n%s\n", pqMnemonicSchemeHeader, formatPQScheme(scheme), mnemonic))
	return os.WriteFile(filename, data, 0600)
}

func readPQMnemonicFile(filename string) (protocol.PQScheme, crypto.Seed, error) {
	if filename == stdinFileNameValue {
		return protocol.PQScheme{}, crypto.Seed{}, fmt.Errorf("refusing to read mnemonic from stdin")
	}
	data, err := readFile(filename)
	if err != nil {
		return protocol.PQScheme{}, crypto.Seed{}, err
	}

	header, mnemonic, ok := bytes.Cut(data, []byte{'\n'})
	if !ok {
		return protocol.PQScheme{}, crypto.Seed{}, fmt.Errorf("%w: missing %q header", errPQKeyMalformed, pqMnemonicSchemeHeader)
	}
	tag, ok := bytes.CutPrefix(bytes.TrimSpace(header), []byte(pqMnemonicSchemeHeader))
	if !ok {
		return protocol.PQScheme{}, crypto.Seed{}, fmt.Errorf("%w: missing %q header", errPQKeyMalformed, pqMnemonicSchemeHeader)
	}

	seed, err := seedFromMnemonic(string(bytes.TrimSpace(mnemonic)))
	if err != nil {
		return protocol.PQScheme{}, crypto.Seed{}, err
	}
	scheme, err := parsePQScheme(string(bytes.TrimSpace(tag)))
	if err != nil {
		return protocol.PQScheme{}, crypto.Seed{}, err
	}
	return scheme, seed, nil
}

func isPQKeyMaterial(data []byte) bool {
	return bytes.HasPrefix(data, []byte(pqPrivateKeyMagic+"\n")) ||
		bytes.HasPrefix(data, []byte(pqPublicKeyMagic+"\n"))
}
