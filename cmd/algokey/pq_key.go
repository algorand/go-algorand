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
	"errors"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errPQKeyMalformed     = errors.New("pq key file is malformed")
	errPQSaltNotCompliant = errors.New("pq address salt is not compliant")
)

// pqPublicMaterial is a PQ public key with its address salt.
type pqPublicMaterial struct {
	_struct struct{} `codec:""`

	Scheme    protocol.PQScheme    `codec:"scheme"`
	Salt      basics.PQAddressSalt `codec:"salt"`
	PublicKey []byte               `codec:"public-key"`
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
	if !m.address().IsPQCompliant() {
		return fmt.Errorf("%w: address %s", errPQSaltNotCompliant, m.address())
	}
	return nil
}

// pqSigningMaterial is a PQ private key with its public envelope. It is also
// the msgp payload of a private key file: key files hold the scheme's working
// keys, never the mnemonic entropy they were derived from.
type pqSigningMaterial struct {
	_struct struct{} `codec:""`

	Public     pqPublicMaterial `codec:"public"`
	PrivateKey []byte           `codec:"private-key"`
}

func (m pqSigningMaterial) validate() error {
	if err := m.Public.validate(); err != nil {
		return err
	}
	ops := pqSchemeOpsByScheme[m.Public.Scheme]
	if uint64(len(m.PrivateKey)) != ops.privateKeySize() {
		return fmt.Errorf("%w: got private key size %d, want %d", errPQKeyMalformed, len(m.PrivateKey), ops.privateKeySize())
	}
	return nil
}

func writePQPrivateKeyFile(filename string, signing pqSigningMaterial) error {
	if err := os.WriteFile(filename, protocol.Encode(&signing), 0600); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", filename, err)
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
	if err := protocol.Decode(data, &signing); err != nil {
		return pqSigningMaterial{}, fmt.Errorf("%w: %w", errPQKeyMalformed, err)
	}
	if err := signing.validate(); err != nil {
		return pqSigningMaterial{}, err
	}
	return signing, nil
}
