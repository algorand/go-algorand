// Copyright (C) 2019-2021 Algorand, Inc.
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

package driver

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/config"
)

const (
	saltLen        = 32
	nonceLen       = 24
	masterKeyLen   = 32
	minScryptN     = 32768
	minScryptR     = 1
	minScryptP     = 32
	hkdfInfoFormat = "AlgorandDeterministicKey-%d"
)

type plaintextType string

var (
	// PTMasterKey is the plaintext type for the master key
	PTMasterKey plaintextType = "master_key"
	// PTSecretKey is the plaintext type for a regular ed25519 secret key
	PTSecretKey plaintextType = "secret_key"
	// PTMasterDerivationKey is the plaintext type for the master derivation key
	PTMasterDerivationKey plaintextType = "master_derivation_key"
	// PTMaxKeyIdx is the plaintext type for the maximum key index
	PTMaxKeyIdx plaintextType = "max_key_idx"
)

// typedPlaintext prevents us from confusing differently typed data encrypted
// under the same key
type typedPlaintext struct {
	Plaintext []byte        `codec:"plaintext"`
	Type      plaintextType `codec:"plaintext_type"`
}

// encryptedDBBlob stores all of the metadata (besides the password) required
// to decrypt a secretbox message
type encryptedDBBlob struct {
	config.ScryptParams
	DoScrypt   bool           `codec:"do_scrypt"`
	Ciphertext []byte         `codec:"ciphertext"`
	Nonce      [nonceLen]byte `codec:"nonce"`
	Salt       [saltLen]byte  `codec:"salt"`
}

// deriveEncryptionKeyWithSalt uses scrypt to derive a key suitable for
// secretbox, but requires that you pass it a salt along with the password
func deriveEncryptionKeyWithSalt(password []byte, salt *[saltLen]byte, cfg config.ScryptParams) (*[masterKeyLen]byte, error) {
	var key [masterKeyLen]byte

	// derive the encryption key from the password + salt
	keySlice, err := scrypt.Key(password, salt[:], cfg.ScryptN, cfg.ScryptR, cfg.ScryptP, masterKeyLen)
	if err != nil {
		err = errDeriveKey
		return nil, err
	}

	// scrypt.Key returns a slice; we need an array pointer
	n := copy(key[:], keySlice)
	if n != masterKeyLen {
		err = errDeriveKey
		return nil, err
	}

	return &key, nil
}

// fillRandomBytes fills a byte slice with random bytes
func fillRandomBytes(out []byte) error {
	// From rand.Read docs: "On return, n == len(b) if and only if err == nil."
	_, err := rand.Read(out)
	if err != nil {
		return errRandBytes
	}
	return nil
}

// deriveEncryptionKey derives a key from the password, returning the key with
// the salt required to generate the same key again.
func deriveEncryptionKey(password []byte, cfg config.ScryptParams) (*[masterKeyLen]byte, *[saltLen]byte, error) {
	var saltArr [saltLen]byte

	// Generate salt
	err := fillRandomBytes(saltArr[:])
	if err != nil {
		return nil, nil, err
	}

	key, err := deriveEncryptionKeyWithSalt(password, &saltArr, cfg)
	return key, &saltArr, err
}

// encryptBlobWithKey takes plaintext and a key, encrypts the plaintext
// using the key, and produces a blob that can be combined with the key
// to produce the plaintext.  It's similar to encryptBlobWithPassword,
// but does not apply scrypt to the input key.
func encryptBlobWithKey(plaintext []byte, ptType plaintextType, key []byte) ([]byte, error) {
	return encryptBlobWithPasswordBlankOK(plaintext, ptType, key, nil)
}

// encryptBlobWithPasswordBlankOK accepts a password, and optionally derives a
// key from it.  If cfg is nil, the password is assumed to be already a
// cryptographic key, and no scrypt key derivation is applied.
func encryptBlobWithPasswordBlankOK(plaintext []byte, ptType plaintextType, password []byte, cfg *config.ScryptParams) (blob []byte, err error) {
	var nonceArr [nonceLen]byte

	// Generate the key and salt
	var key *[masterKeyLen]byte
	var salt *[saltLen]byte
	if cfg != nil {
		key, salt, err = deriveEncryptionKey(password, *cfg)
		if err != nil {
			return
		}
	} else {
		if len(password) != masterKeyLen {
			err = errDeriveKey
			return
		}
		key = new([masterKeyLen]byte)
		copy(key[:], password)
	}

	// Generate the nonce
	err = fillRandomBytes(nonceArr[:])
	if err != nil {
		return
	}

	// Give the plaintext a type
	typedPT := typedPlaintext{
		Plaintext: plaintext,
		Type:      ptType,
	}

	// Encode & encrypt the typed plaintext
	encodedPT := msgpackEncode(typedPT)
	ciphertext := secretbox.Seal(nil, encodedPT, &nonceArr, key)

	// Build the encrypted database blob
	dbblob := encryptedDBBlob{
		Ciphertext: ciphertext,
		Nonce:      nonceArr,
	}

	if cfg != nil {
		dbblob.ScryptParams = *cfg
		dbblob.DoScrypt = true
		dbblob.Salt = *salt
	} else {
		dbblob.DoScrypt = false
	}

	// Encode to msgpack
	blob = msgpackEncode(dbblob)
	return
}

func decryptBlobWithPassword(blob []byte, ptType plaintextType, password []byte) (plaintext []byte, err error) {
	// Decode blob from msgpack
	var dbblob encryptedDBBlob
	err = msgpackDecode(blob, &dbblob)
	if err != nil {
		return
	}

	// Derive the encryption key
	var key *[masterKeyLen]byte
	if dbblob.DoScrypt {
		key, err = deriveEncryptionKeyWithSalt(password, &dbblob.Salt, dbblob.ScryptParams)
		if err != nil {
			return
		}
	} else {
		if len(password) != masterKeyLen {
			err = errDeriveKey
			return
		}
		key = new([masterKeyLen]byte)
		copy(key[:], password)
	}

	// Decrypt the ciphertext
	encodedPT, ok := secretbox.Open(nil, dbblob.Ciphertext, &dbblob.Nonce, key)
	if !ok {
		return nil, errDecrypt
	}

	// Decode the typedPlaintext
	var typedPT typedPlaintext
	err = msgpackDecode(encodedPT, &typedPT)
	if err != nil {
		return
	}

	// Make sure the type is what we expected
	if typedPT.Type != ptType {
		err = errTypeMismatch
		return
	}

	return typedPT.Plaintext, nil
}

// extractKeyWithIndex accepts the master derivation key and an index which
// specifies the key to be derived
func extractKeyWithIndex(derivationKey []byte, index uint64) (pk crypto.PublicKey, sk crypto.PrivateKey, err error) {
	// The info tag is just the the utf-8 string representation of the index
	info := []byte(fmt.Sprintf(hkdfInfoFormat, index))

	// We can skip hkdf.Extract since our key is long and uniformly random
	// Use the master derivation key and the index to generate a keystream
	hash := sha512.New512_256
	keystream := hkdf.Expand(hash, derivationKey, info)

	// Read an ed25519 seed from the keystream
	var seed crypto.Seed
	_, err = io.ReadFull(keystream, seed[:])
	if err != nil {
		err = errRandBytes
		return
	}

	// Convert the seed into signature secrets deterministically
	secrets := crypto.GenerateSignatureSecrets(seed)

	// Return the generated public key and corresponding secret key
	return crypto.PublicKey(secrets.SignatureVerifier), crypto.PrivateKey(secrets.SK), nil
}

// fastHashWithSalt returns a salted hash of a password, using a fast hash function
func fastHashWithSalt(password []byte, salt []byte) crypto.Digest {
	return crypto.Hash(append(salt, password...))
}
