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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type countingRNG struct {
	calls int
	bytes int
}

func (rng *countingRNG) RandBytes(buf []byte) {
	rng.calls++
	rng.bytes += len(buf)
	for i := range buf {
		buf[i] = byte(i + 1)
	}
}

func pqTestMaterial(t *testing.T, firstSeedByte byte) pqKeyMaterial {
	t.Helper()

	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	signer, err := crypto.GenerateFalconSigner(seed)
	require.NoError(t, err)

	publicKey := slices.Clone(signer.PublicKey[:])
	privateKey := slices.Clone(signer.PrivateKey[:])
	salt, addr, err := basics.CanonicalPQAddressSalt(protocol.PQSchemeFalcon1024, publicKey)
	require.NoError(t, err)

	return pqKeyMaterial{
		scheme:           protocol.PQSchemeFalcon1024,
		publicKey:        publicKey,
		privateKey:       privateKey,
		canonicalSalt:    salt,
		canonicalAddress: addr,
	}
}

func pqTestTxn(sender basics.Address) transactions.SignedTxn {
	return transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender: sender,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: sender,
			},
		},
	}
}

func TestPQGenerateUsesFalconSeedEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rng := &countingRNG{}

	material, err := generateFalcon1024Key(rng)
	require.NoError(t, err)
	require.Equal(t, 1, rng.calls)
	require.Equal(t, crypto.FalconSeedSize, rng.bytes)
	require.Equal(t, protocol.PQSchemeFalcon1024, material.scheme)
	require.True(t, material.canonicalAddress.IsPQCompliant())
	require.NoError(t, validateFalcon1024KeyPair(material.publicKey, material.privateKey))
}

func TestPQSchemeLookupsSplitSharedMetadataAndLocalOps(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	registrySpec, ok := basics.LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)
	spec, err := lookupPQScheme(protocol.PQSchemeFalcon1024)
	require.NoError(t, err)
	require.Equal(t, registrySpec.PublicKeySize, spec.PublicKeySize)
	require.Equal(t, registrySpec.SignatureSize, spec.SignatureSize)

	ops, err := opsForPQScheme(protocol.PQSchemeFalcon1024)
	require.NoError(t, err)
	require.Equal(t, "Falcon-1024", ops.displayName)
	require.Equal(t, uint64(crypto.FalconPrivateKeySize), ops.privateKeySize)
	require.NotNil(t, ops.generate)
	require.NotNil(t, ops.signTxn)
	require.NotNil(t, ops.validateKeyPair)

	unsupportedScheme := protocol.PQScheme("zz")
	_, err = lookupPQScheme(unsupportedScheme)
	require.ErrorIs(t, err, basics.ErrPQSchemeNotSupported)
	_, err = opsForPQScheme(unsupportedScheme)
	require.ErrorIs(t, err, basics.ErrPQSchemeNotSupported)
}

func TestPQSchemeRegistriesConsistent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Every algokey tooling scheme must be backed by the consensus registry,
	// and its ops entry must be complete.
	for scheme, ops := range pqSchemeOpsByScheme {
		_, ok := basics.LookupPQScheme(scheme)
		require.True(t, ok, "algokey scheme %q missing from basics registry", scheme)
		require.NotEmpty(t, ops.displayName, "scheme %q", scheme)
		require.NotZero(t, ops.privateKeySize, "scheme %q", scheme)
		require.NotNil(t, ops.generate, "scheme %q", scheme)
		require.NotNil(t, ops.signTxn, "scheme %q", scheme)
		require.NotNil(t, ops.validateKeyPair, "scheme %q", scheme)
	}

	// Every currently supported basics scheme must have signing/private-key tooling.
	for _, scheme := range []protocol.PQScheme{protocol.PQSchemeFalcon1024} {
		_, ok := pqSchemeOpsByScheme[scheme]
		require.True(t, ok, "basics scheme %q missing from algokey ops registry", scheme)
	}
}

func TestPQPrivateKeyFileRoundTripAndPermissions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 0)
	keyfile := filepath.Join(t.TempDir(), "account.pq")

	require.NoError(t, writePQPrivateKeyFile(keyfile, material))

	info, err := os.Stat(keyfile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	decoded, err := readPQPrivateKeyFile(keyfile)
	require.NoError(t, err)
	require.Equal(t, material.scheme, decoded.scheme)
	require.Equal(t, material.publicKey, decoded.publicKey)
	require.Equal(t, material.privateKey, decoded.privateKey)
	require.Equal(t, material.canonicalSalt, decoded.canonicalSalt)
	require.Equal(t, material.canonicalAddress, decoded.canonicalAddress)

	require.ErrorIs(t, writePQPrivateKeyFile(keyfile, material), os.ErrExist)
}

func TestPQKeyFilesDoNotPersistSaltOrAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 1)
	changed := material
	changed.canonicalSalt++
	changed.canonicalAddress[0] ^= 1

	require.Equal(t, encodePQPrivateKeyFileBytes(material), encodePQPrivateKeyFileBytes(changed))
	require.Equal(t, encodePQPublicKeyFileBytes(material), encodePQPublicKeyFileBytes(changed))
}

func TestPQKeyFileRejectsMalformedInputs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 0)

	var edSeed crypto.Seed
	_, err := decodePQPrivateKeyFileBytes(edSeed[:])
	require.ErrorIs(t, err, errPQKeyWrongType)

	payload := pqPrivateKeyPayload{
		Scheme:     protocol.PQScheme("zz"),
		PublicKey:  material.publicKey,
		PrivateKey: material.privateKey,
	}
	_, err = decodePQPrivateKeyFileBytes(encodePQPayload(pqPrivateKeyMagic, payload))
	require.ErrorIs(t, err, basics.ErrPQSchemeNotSupported)

	payload.Scheme = protocol.PQSchemeFalcon1024
	payload.PublicKey = payload.PublicKey[:len(payload.PublicKey)-1]
	_, err = decodePQPrivateKeyFileBytes(encodePQPayload(pqPrivateKeyMagic, payload))
	require.ErrorIs(t, err, errPQKeyMalformed)

	payload.PublicKey = material.publicKey
	payload.PrivateKey = payload.PrivateKey[:len(payload.PrivateKey)-1]
	_, err = decodePQPrivateKeyFileBytes(encodePQPayload(pqPrivateKeyMagic, payload))
	require.ErrorIs(t, err, errPQKeyMalformed)
}

func TestPQArmorRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 0)
	keyData := encodePQPrivateKeyFileBytes(material)

	armor := string(armorPQPrivateKeyBytes(material.scheme, keyData))
	require.Contains(t, armor, pqArmorBegin)
	require.Contains(t, armor, "Scheme: f1")
	require.Contains(t, armor, pqArmorEncoding)
	require.NotContains(t, armor, "Version:")

	decoded, scheme, err := decodeArmoredPQPrivateKey([]byte(armor))
	require.NoError(t, err)
	require.Equal(t, protocol.PQSchemeFalcon1024, scheme)
	require.Equal(t, keyData, decoded)

	_, _, err = decodeArmoredPQPrivateKey([]byte(strings.Replace(armor, "Scheme: f1", "Scheme: zz", 1)))
	require.ErrorIs(t, err, basics.ErrPQSchemeNotSupported)

	_, _, err = decodeArmoredPQPrivateKey([]byte("not an armored key"))
	require.ErrorIs(t, err, errPQArmorMalformed)
}

func TestPQImportRejectsArmoredMalformedPayload(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 0)
	payload := pqPrivateKeyPayload{
		Scheme:     material.scheme,
		PublicKey:  material.publicKey,
		PrivateKey: material.privateKey[:len(material.privateKey)-1],
	}
	badData := encodePQPayload(pqPrivateKeyMagic, payload)
	defer zeroBytes(badData)
	armor := armorPQPrivateKeyBytes(material.scheme, badData)
	defer zeroBytes(armor)

	tempDir := t.TempDir()
	importInfile := filepath.Join(tempDir, "bad.pq")
	importKeyfile := filepath.Join(tempDir, "imported.pq")
	require.NoError(t, os.WriteFile(importInfile, armor, 0600))

	err := runPQImportWithOptions(pqImportOptions{
		infile:  importInfile,
		keyfile: importKeyfile,
	})
	require.ErrorIs(t, err, errPQKeyMalformed)

	_, statErr := os.Stat(importKeyfile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestPQPublicAddressSaltHandling(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 1)
	require.Equal(t, basics.PQAddressSalt(1), material.canonicalSalt)

	salt, addr, err := resolvePQSalt(material.scheme, material.publicKey, "canonical")
	require.NoError(t, err)
	require.Equal(t, material.canonicalSalt, salt)
	require.Equal(t, material.canonicalAddress, addr)
	require.True(t, addr.IsPQCompliant())

	salt, addr, err = resolvePQSalt(material.scheme, material.publicKey, "0")
	require.NoError(t, err)
	require.Equal(t, basics.PQAddressSalt(0), salt)
	require.Equal(t, basics.PQAddress(material.scheme, salt, material.publicKey), addr)
	require.False(t, addr.IsPQCompliant())

	_, _, err = resolvePQSalt(material.scheme, material.publicKey, "256")
	require.ErrorContains(t, err, "invalid pq salt")
}

func TestPQSignProducesVerifiablePQEnvelope(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQPrivateKeyFile(keyfile, material))

	stxn := pqTestTxn(material.canonicalAddress)
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
		salt:    "canonical",
	}))

	signedBytes, err := os.ReadFile(outfile)
	require.NoError(t, err)
	var signed transactions.SignedTxn
	require.NoError(t, protocol.Decode(signedBytes, &signed))

	require.True(t, signed.Sig.Blank())
	require.True(t, signed.Msig.Blank())
	require.True(t, signed.Lsig.Blank())
	require.False(t, signed.PQSig.Blank())
	require.True(t, signed.AuthAddr.IsZero())
	require.Equal(t, material.canonicalAddress, signed.Authorizer())
	require.Equal(t, protocol.PQSchemeFalcon1024, signed.PQSig.Scheme)
	require.Equal(t, material.canonicalSalt, signed.PQSig.Salt)
	require.Equal(t, material.publicKey, signed.PQSig.PublicKey)
	require.NoError(t, signed.PQSig.Verify(config.Consensus[protocol.ConsensusFuture], signed.Txn, signed.Authorizer()))

	changed := signed
	changed.Txn.Note = []byte("changed")
	require.ErrorContains(t, changed.PQSig.Verify(config.Consensus[protocol.ConsensusFuture], changed.Txn, changed.Authorizer()), "invalid falcon-1024 signature")
}

func TestPQSignSetsAndClearsAuthAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	require.NoError(t, writePQPrivateKeyFile(keyfile, material))

	var sender basics.Address
	sender[0] = 9
	txfile := filepath.Join(tempDir, "rekey.msgp")
	outfile := filepath.Join(tempDir, "rekey-signed.msgp")
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&transactions.SignedTxn{Txn: pqTestTxn(sender).Txn}), 0600))
	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
		salt:    "canonical",
	}))
	var signed transactions.SignedTxn
	data, err := os.ReadFile(outfile)
	require.NoError(t, err)
	require.NoError(t, protocol.Decode(data, &signed))
	require.Equal(t, material.canonicalAddress, signed.AuthAddr)

	var stale basics.Address
	stale[0] = 10
	txfile = filepath.Join(tempDir, "stale.msgp")
	outfile = filepath.Join(tempDir, "stale-signed.msgp")
	stxn := pqTestTxn(material.canonicalAddress)
	stxn.AuthAddr = stale
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))
	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
		salt:    "canonical",
	}))
	data, err = os.ReadFile(outfile)
	require.NoError(t, err)
	var staleSigned transactions.SignedTxn
	require.NoError(t, protocol.Decode(data, &staleSigned))
	require.True(t, staleSigned.AuthAddr.IsZero())
}

func TestPQSignRejectsMixedSignaturesUnlessOverwrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQPrivateKeyFile(keyfile, material))

	stxn := pqTestTxn(material.canonicalAddress)
	stxn.Sig[0] = 1
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	err := runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
		salt:    "canonical",
	})
	require.ErrorIs(t, err, errPQTxnAlreadySigned)

	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile:   keyfile,
		txfile:    txfile,
		outfile:   outfile,
		salt:      "canonical",
		overwrite: true,
	}))
	data, err := os.ReadFile(outfile)
	require.NoError(t, err)
	var signed transactions.SignedTxn
	require.NoError(t, protocol.Decode(data, &signed))
	require.True(t, signed.Sig.Blank())
	require.False(t, signed.PQSig.Blank())
}

func TestPQSignRejectsNonCompliantSalt(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 1)
	require.Equal(t, basics.PQAddressSalt(1), material.canonicalSalt)

	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQPrivateKeyFile(keyfile, material))
	stxn := pqTestTxn(material.canonicalAddress)
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	err := runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
		salt:    "0",
	})
	require.ErrorIs(t, err, errPQSaltNotCompliant)
}

func TestPQMaterialDetection(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	material := pqTestMaterial(t, 0)
	require.True(t, isPQKeyMaterial(encodePQPrivateKeyFileBytes(material)))
	require.True(t, isPQKeyMaterial(encodePQPublicKeyFileBytes(material)))
	require.True(t, isPQKeyMaterial(armorPQPrivateKeyBytes(material.scheme, encodePQPrivateKeyFileBytes(material))))

	var edSeed crypto.Seed
	require.False(t, isPQKeyMaterial(edSeed[:]))
}

func TestPQDecodeArmorRejectsMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	_, _, err := decodeArmoredPQPrivateKey([]byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
	require.ErrorIs(t, err, errPQArmorMalformed)
}
