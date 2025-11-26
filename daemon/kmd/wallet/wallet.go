// Copyright (C) 2019-2025 Algorand, Inc.
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

package wallet

import (
	"crypto/rand"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const (
	walletIDBytes = 16
)

// Wallet represents the interface that any wallet technology must satisfy in
// order to be used with KMD. Wallets start in a locked state until they are
// initialized with Init.
type Wallet interface {
	Init(pw []byte) error
	CheckPassword(pw []byte) error
	ExportMasterDerivationKey(pw []byte) (crypto.MasterDerivationKey, error)

	Metadata() (Metadata, error)

	ListKeys() ([]crypto.Digest, error)

	ImportKey(sk crypto.PrivateKey) (crypto.Digest, error)
	ExportKey(pk crypto.Digest, pw []byte) (crypto.PrivateKey, error)
	GenerateKey(displayMnemonic bool) (crypto.Digest, error)
	DeleteKey(pk crypto.Digest, pw []byte) error

	ImportMultisigAddr(version, threshold uint8, pks []crypto.PublicKey) (crypto.Digest, error)
	LookupMultisigPreimage(crypto.Digest) (version, threshold uint8, pks []crypto.PublicKey, err error)
	ListMultisigAddrs() (addrs []crypto.Digest, err error)
	DeleteMultisigAddr(addr crypto.Digest, pw []byte) error

	SignTransaction(tx transactions.Transaction, pk crypto.PublicKey, pw []byte) ([]byte, error)

	MultisigSignTransaction(tx transactions.Transaction, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte, signer crypto.Digest) (crypto.MultisigSig, error)

	SignProgram(program []byte, src crypto.Digest, pw []byte) ([]byte, error)
	MultisigSignProgram(program []byte, src crypto.Digest, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte, useLegacyMsig bool) (crypto.MultisigSig, error)
}

// Metadata represents high-level information about a wallet, like its name, id
// and what operations it supports
type Metadata struct {
	ID                    []byte
	Name                  []byte
	DriverName            string
	DriverVersion         uint32
	SupportsMnemonicUX    bool
	SupportsMasterKey     bool
	SupportedTransactions []protocol.TxType
}

// GenerateWalletID generates a random hex wallet ID
func GenerateWalletID() ([]byte, error) {
	bytes := make([]byte, walletIDBytes)
	_, err := rand.Read(bytes)
	if err != nil {
		return []byte(""), err
	}
	return []byte(fmt.Sprintf("%x", bytes)), nil
}
