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

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

const (
	pqPrivateKeyMagic = "ALGO-PQ-PRIVATE"
	pqPublicKeyMagic  = "ALGO-PQ-PUBLIC"
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

func (m pqPublicMaterial) validate() error {
	ops, ok := pqSchemeOpsByScheme[m.Scheme]
	if !ok {
		return fmt.Errorf("%w: %q", crypto.ErrPQSchemeNotSupported, m.Scheme)
	}
	if uint64(len(m.PublicKey)) != ops.publicKeySize() {
		return fmt.Errorf("%w: got public key size %d, want %d", errPQKeyMalformed, len(m.PublicKey), ops.publicKeySize())
	}
	return nil
}

// pqSigningMaterial is a PQ private key with its public envelope. It is also
// the msgp payload stored after the PQ private-key magic prefix: key files
// hold the scheme's working keys, never the mnemonic entropy they were
// derived from.
type pqSigningMaterial struct {
	_struct struct{} `codec:""`

	Public     pqPublicMaterial `codec:"public"`
	PrivateKey []byte           `codec:"private-key,allocbound=maxPQPrivateKeySize"`
}

func writePQPrivateKeyFile(filename string, signing pqSigningMaterial) error {
	data := encodePQPayload(pqPrivateKeyMagic, &signing)
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

func readPQSigningMaterial(filename string) (pqSigningMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqSigningMaterial{}, fmt.Errorf("cannot read private key from %s: %w", filename, err)
	}
	return decodePQPrivateKeyFileBytes(data)
}

func decodePQPrivateKeyFileBytes(data []byte) (pqSigningMaterial, error) {
	var signing pqSigningMaterial
	if err := decodePQPayload(data, pqPrivateKeyMagic, &signing); err != nil {
		return pqSigningMaterial{}, err
	}
	if err := signing.Public.validate(); err != nil {
		return pqSigningMaterial{}, err
	}
	return signing, nil
}

// readPQKeyFilePublic reads the public material from either a private or a
// public key file.
func readPQKeyFilePublic(filename string) (pqPublicMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqPublicMaterial{}, fmt.Errorf("cannot read key file from %s: %w", filename, err)
	}
	if bytes.HasPrefix(data, []byte(pqPublicKeyMagic+"\n")) {
		return decodePQPublicKeyFileBytes(data)
	}
	signing, err := decodePQPrivateKeyFileBytes(data)
	if err != nil {
		return pqPublicMaterial{}, err
	}
	return signing.Public, nil
}

func encodePQPayload(magic string, payload msgp.Marshaler) []byte {
	return append([]byte(magic+"\n"), protocol.Encode(payload)...)
}

func decodePQPublicKeyFileBytes(data []byte) (pqPublicMaterial, error) {
	var public pqPublicMaterial
	if err := decodePQPayload(data, pqPublicKeyMagic, &public); err != nil {
		return pqPublicMaterial{}, err
	}
	if err := public.validate(); err != nil {
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

func isPQKeyMaterial(data []byte) bool {
	return bytes.HasPrefix(data, []byte(pqPrivateKeyMagic+"\n")) ||
		bytes.HasPrefix(data, []byte(pqPublicKeyMagic+"\n"))
}
