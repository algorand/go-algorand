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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

const (
	pqPrivateKeyMagic = "ALGOKEY-PQ-PRIVATE"
	pqPublicKeyMagic  = "ALGOKEY-PQ-PUBLIC"

	pqArmorBegin    = "-----BEGIN ALGOKEY PQ PRIVATE KEY-----"
	pqArmorEnd      = "-----END ALGOKEY PQ PRIVATE KEY-----"
	pqArmorEncoding = "Encoding: base64"
	pqArmorLineLen  = 64
)

var (
	errPQKeyWrongType     = errors.New("pq key file has the wrong type")
	errPQKeyMalformed     = errors.New("pq key file is malformed")
	errPQSaltNotCompliant = errors.New("pq address salt is not compliant")
	errPQArmorMalformed   = errors.New("pq armored private key is malformed")
)

type pqKeyMaterial struct {
	scheme           protocol.PQScheme
	publicKey        []byte
	privateKey       []byte
	canonicalSalt    basics.PQAddressSalt
	canonicalAddress basics.Address
}

type pqPrivateKeyPayload struct {
	Scheme     protocol.PQScheme `codec:"scheme"`
	PublicKey  []byte            `codec:"public-key"`
	PrivateKey []byte            `codec:"private-key"`
}

type pqPublicKeyPayload struct {
	Scheme    protocol.PQScheme `codec:"scheme"`
	PublicKey []byte            `codec:"public-key"`
}

func writePQPrivateKeyFile(filename string, material pqKeyMaterial) error {
	data := encodePQPrivateKeyFileBytes(material)
	defer zeroBytes(data)
	if err := writeNewFile(filename, data, 0600); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", filename, err)
	}
	return nil
}

func writePQPublicKeyFile(filename string, material pqKeyMaterial) error {
	data := encodePQPublicKeyFileBytes(material)
	if err := writeNewFile(filename, data, 0666); err != nil {
		return fmt.Errorf("cannot write public key to %s: %w", filename, err)
	}
	return nil
}

func readPQPrivateKeyFile(filename string) (pqKeyMaterial, error) {
	data, material, err := readPQPrivateKeyFileData(filename)
	if err != nil {
		return pqKeyMaterial{}, err
	}
	zeroBytes(data)
	return material, nil
}

func readPQPrivateKeyFileData(filename string) ([]byte, pqKeyMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return nil, pqKeyMaterial{}, fmt.Errorf("cannot read private key from %s: %w", filename, err)
	}
	material, err := decodePQPrivateKeyFileBytes(data)
	if err != nil {
		zeroBytes(data)
		return nil, pqKeyMaterial{}, err
	}
	return data, material, nil
}

func readPQPublicKeyFile(filename string) (pqKeyMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqKeyMaterial{}, fmt.Errorf("cannot read public key from %s: %w", filename, err)
	}
	return decodePQPublicKeyFileBytes(data)
}

func encodePQPrivateKeyFileBytes(material pqKeyMaterial) []byte {
	privateKey := slices.Clone(material.privateKey)
	defer zeroBytes(privateKey)
	payload := pqPrivateKeyPayload{
		Scheme:     material.scheme,
		PublicKey:  slices.Clone(material.publicKey),
		PrivateKey: privateKey,
	}
	return encodePQPayload(pqPrivateKeyMagic, payload)
}

func encodePQPublicKeyFileBytes(material pqKeyMaterial) []byte {
	payload := pqPublicKeyPayload{
		Scheme:    material.scheme,
		PublicKey: slices.Clone(material.publicKey),
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

func decodePQPrivateKeyFileBytes(data []byte) (pqKeyMaterial, error) {
	var payload pqPrivateKeyPayload
	if err := decodePQPayload(data, pqPrivateKeyMagic, &payload); err != nil {
		zeroBytes(payload.PrivateKey)
		return pqKeyMaterial{}, err
	}
	defer zeroBytes(payload.PrivateKey)
	return materialFromPrivatePayload(payload)
}

func decodePQPublicKeyFileBytes(data []byte) (pqKeyMaterial, error) {
	var payload pqPublicKeyPayload
	if err := decodePQPayload(data, pqPublicKeyMagic, &payload); err != nil {
		return pqKeyMaterial{}, err
	}
	return materialFromPublicFields(payload.Scheme, payload.PublicKey)
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

func materialFromPrivatePayload(payload pqPrivateKeyPayload) (pqKeyMaterial, error) {
	material, err := materialFromPublicFields(payload.Scheme, payload.PublicKey)
	if err != nil {
		return pqKeyMaterial{}, err
	}

	ops, err := opsForPQScheme(payload.Scheme)
	if err != nil {
		return pqKeyMaterial{}, err
	}
	if uint64(len(payload.PrivateKey)) != ops.privateKeySize {
		return pqKeyMaterial{}, fmt.Errorf("%w: got private key size %d, want %d", errPQKeyMalformed, len(payload.PrivateKey), ops.privateKeySize)
	}
	material.privateKey = slices.Clone(payload.PrivateKey)
	if ops.validateKeyPair != nil {
		if err = ops.validateKeyPair(material.publicKey, material.privateKey); err != nil {
			wipePQKeyMaterial(&material)
			return pqKeyMaterial{}, err
		}
	}
	return material, nil
}

func materialFromPublicFields(scheme protocol.PQScheme, publicKey []byte) (pqKeyMaterial, error) {
	spec, err := lookupPQScheme(scheme)
	if err != nil {
		return pqKeyMaterial{}, err
	}
	if uint64(len(publicKey)) != spec.PublicKeySize {
		return pqKeyMaterial{}, fmt.Errorf("%w: got public key size %d, want %d", errPQKeyMalformed, len(publicKey), spec.PublicKeySize)
	}
	if err = spec.ValidatePublicKey(publicKey); err != nil {
		return pqKeyMaterial{}, err
	}

	canonicalSalt, canonicalAddress, err := basics.CanonicalPQAddressSalt(scheme, publicKey)
	if err != nil {
		return pqKeyMaterial{}, err
	}
	if !canonicalAddress.IsPQCompliant() {
		return pqKeyMaterial{}, fmt.Errorf("%w: canonical address %s", errPQSaltNotCompliant, canonicalAddress)
	}

	return pqKeyMaterial{
		scheme:           scheme,
		publicKey:        slices.Clone(publicKey),
		canonicalSalt:    canonicalSalt,
		canonicalAddress: canonicalAddress,
	}, nil
}

// resolvePQSalt resolves saltValue ("canonical", or a decimal in 0..255) to a
// salt and its derived PQ address for the given scheme and public key. The
// canonical salt always derives a compliant address; for an explicit salt,
// callers decide how to treat non-compliant addresses via addr.IsPQCompliant().
func resolvePQSalt(scheme protocol.PQScheme, publicKey []byte, saltValue string) (basics.PQAddressSalt, basics.Address, error) {
	spec, err := lookupPQScheme(scheme)
	if err != nil {
		return 0, basics.Address{}, err
	}
	if err = spec.ValidatePublicKey(publicKey); err != nil {
		return 0, basics.Address{}, err
	}

	if saltValue == "" || strings.EqualFold(saltValue, "canonical") {
		return basics.CanonicalPQAddressSalt(scheme, publicKey)
	}

	n, err := strconv.ParseUint(saltValue, 10, 8)
	if err != nil {
		return 0, basics.Address{}, fmt.Errorf("invalid pq salt %q: use canonical or 0..255", saltValue)
	}
	salt := basics.PQAddressSalt(n)
	return salt, basics.PQAddress(scheme, salt, publicKey), nil
}

func armorPQPrivateKeyBytes(scheme protocol.PQScheme, data []byte) []byte {
	var out []byte
	out = append(out, pqArmorBegin...)
	out = append(out, '\n')
	out = append(out, "Scheme: "...)
	out = append(out, string(scheme)...)
	out = append(out, '\n')
	out = append(out, pqArmorEncoding...)
	out = append(out, "\n\n"...)

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	defer zeroBytes(encoded)
	base64.StdEncoding.Encode(encoded, data)
	remaining := encoded
	for len(remaining) > pqArmorLineLen {
		out = append(out, remaining[:pqArmorLineLen]...)
		out = append(out, '\n')
		remaining = remaining[pqArmorLineLen:]
	}
	out = append(out, remaining...)
	out = append(out, '\n')
	out = append(out, pqArmorEnd...)
	out = append(out, '\n')
	return out
}

func decodeArmoredPQPrivateKey(armor []byte) ([]byte, protocol.PQScheme, error) {
	lines := bytes.Split(armor, []byte{'\n'})
	if len(lines) < 6 || !bytes.Equal(bytes.TrimSpace(lines[0]), []byte(pqArmorBegin)) {
		return nil, "", errPQArmorMalformed
	}

	schemePrefix := []byte("Scheme: ")
	schemeLine := bytes.TrimSpace(lines[1])
	if !bytes.HasPrefix(schemeLine, schemePrefix) {
		return nil, "", errPQArmorMalformed
	}
	scheme := protocol.PQScheme(string(bytes.TrimSpace(bytes.TrimPrefix(schemeLine, schemePrefix))))
	if _, err := lookupPQScheme(scheme); err != nil {
		return nil, "", err
	}

	if !bytes.Equal(bytes.TrimSpace(lines[2]), []byte(pqArmorEncoding)) {
		return nil, "", errPQArmorMalformed
	}
	if len(bytes.TrimSpace(lines[3])) != 0 {
		return nil, "", errPQArmorMalformed
	}

	encoded := make([]byte, 0, len(armor))
	// Deferred argument evaluation would capture the zero-length slice header
	// before the appends below; the closure wipes the final contents instead.
	defer func() { zeroBytes(encoded) }()
	foundEnd := false
	endIndex := -1
	for i, line := range lines[4:] {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if bytes.Equal(line, []byte(pqArmorEnd)) {
			foundEnd = true
			endIndex = i + 4
			break
		}
		encoded = append(encoded, line...)
	}
	if !foundEnd {
		return nil, "", errPQArmorMalformed
	}
	for _, line := range lines[endIndex+1:] {
		if len(bytes.TrimSpace(line)) != 0 {
			return nil, "", errPQArmorMalformed
		}
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil {
		zeroBytes(decoded)
		return nil, "", fmt.Errorf("%w: %w", errPQArmorMalformed, err)
	}
	data := decoded[:n]

	material, err := decodePQPrivateKeyFileBytes(data)
	if err != nil {
		zeroBytes(data)
		return nil, "", err
	}
	defer wipePQKeyMaterial(&material)
	if material.scheme != scheme {
		zeroBytes(data)
		return nil, "", fmt.Errorf("%w: armor scheme is %q, payload scheme is %q", errPQKeyMalformed, scheme, material.scheme)
	}
	return data, scheme, nil
}

func isPQKeyMaterial(data []byte) bool {
	return bytes.HasPrefix(data, []byte(pqPrivateKeyMagic+"\n")) ||
		bytes.HasPrefix(data, []byte(pqPublicKeyMagic+"\n")) ||
		bytes.HasPrefix(data, []byte(pqArmorBegin))
}

func writeNewFile(filename string, data []byte, perm os.FileMode) error {
	if filename == stdoutFilenameValue {
		return fmt.Errorf("refusing to write key file to stdout")
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return closeErr
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
}

func wipePQKeyMaterial(material *pqKeyMaterial) {
	zeroBytes(material.privateKey)
	material.privateKey = nil
}
