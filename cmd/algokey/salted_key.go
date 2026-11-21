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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errSaltedKeyMalformed = errors.New("key file is malformed")
	errSaltOnCurve        = errors.New("address salt puts the address on the Ed25519 curve")
)

// saltedPublicMaterial is a signature-scheme public key with its address salt.
type saltedPublicMaterial struct {
	_struct struct{} `codec:""`

	Scheme    protocol.SigScheme `codec:"scheme"`
	Salt      basics.AddressSalt `codec:"salt"`
	PublicKey []byte             `codec:"public-key"`
}

func (m saltedPublicMaterial) address() basics.Address {
	return basics.SaltedAddress(m.Scheme, m.Salt, m.PublicKey)
}

func (m saltedPublicMaterial) validate() error {
	ops, ok := sigSchemeOpsByScheme[m.Scheme]
	if !ok {
		return fmt.Errorf("%w: %q", transactions.ErrSigSchemeNotSupported, m.Scheme)
	}
	if uint64(len(m.PublicKey)) != ops.publicKeySize() {
		return fmt.Errorf("%w: got public key size %d, want %d", errSaltedKeyMalformed, len(m.PublicKey), ops.publicKeySize())
	}
	if !m.address().IsOffEd25519Curve() {
		return fmt.Errorf("%w: address %s", errSaltOnCurve, m.address())
	}
	return nil
}

// saltedSigningMaterial is a signature-scheme private key with its public envelope. It is also
// the msgp payload of a private key file: key files hold the scheme's working
// keys, never the mnemonic entropy they were derived from.
type saltedSigningMaterial struct {
	_struct struct{} `codec:""`

	Public     saltedPublicMaterial `codec:"public"`
	PrivateKey []byte               `codec:"private-key"`
}

func (m saltedSigningMaterial) validate() error {
	if err := m.Public.validate(); err != nil {
		return err
	}
	ops := sigSchemeOpsByScheme[m.Public.Scheme]
	if uint64(len(m.PrivateKey)) != ops.privateKeySize() {
		return fmt.Errorf("%w: got private key size %d, want %d", errSaltedKeyMalformed, len(m.PrivateKey), ops.privateKeySize())
	}
	return nil
}

func writeSaltedPrivateKeyFile(filename string, signing saltedSigningMaterial) error {
	if err := os.WriteFile(filename, protocol.Encode(&signing), 0600); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", filename, err)
	}
	return nil
}

func readSaltedSigningMaterial(filename string) (saltedSigningMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return saltedSigningMaterial{}, fmt.Errorf("cannot read private key from %s: %w", filename, err)
	}
	return decodeSaltedPrivateKeyFileBytes(data)
}

func decodeSaltedPrivateKeyFileBytes(data []byte) (saltedSigningMaterial, error) {
	var signing saltedSigningMaterial
	if err := protocol.Decode(data, &signing); err != nil {
		return saltedSigningMaterial{}, fmt.Errorf("%w: %w", errSaltedKeyMalformed, err)
	}
	if err := signing.validate(); err != nil {
		return saltedSigningMaterial{}, err
	}
	return signing, nil
}
