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
	"strconv"
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

func pqTestRoot(t *testing.T, firstEntropyByte byte) pqRootMaterial {
	t.Helper()

	var entropy crypto.Seed
	entropy[0] = firstEntropyByte
	defer zeroBytes(entropy[:])

	root, err := rootMaterialFromEntropy(protocol.PQSchemeFalcon1024, entropy)
	require.NoError(t, err)
	return root
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

func requirePQPublicEqual(t *testing.T, expected, actual pqPublicMaterial) {
	t.Helper()
	require.Equal(t, expected.scheme, actual.scheme)
	require.Equal(t, expected.salt, actual.salt)
	require.Equal(t, expected.pk, actual.pk)
	require.Equal(t, expected.addr, actual.addr)
}

func nonCompliantPQPublic(t *testing.T, public pqPublicMaterial) pqPublicMaterial {
	t.Helper()
	for i := 0; i <= 255; i++ {
		candidate, err := resolvePQSalt(public, strconv.Itoa(i))
		require.NoError(t, err)
		if !candidate.addr.IsPQCompliant() {
			return candidate
		}
	}
	t.Fatal("expected at least one non-compliant PQ address salt")
	return pqPublicMaterial{}
}

func TestPQKeySeedDerivationUsesDomainSchemeAndEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	for i := range entropy {
		entropy[i] = byte(i)
	}

	seed, err := derivePQKeySeed(protocol.PQSchemeFalcon1024, entropy[:])
	require.NoError(t, err)

	preimage := make([]byte, 0, len(protocol.PostQuantumKey)+protocol.PQSchemeSize+len(entropy))
	preimage = append(preimage, string(protocol.PostQuantumKey)...)
	preimage = append(preimage, string(protocol.PQSchemeFalcon1024)...)
	preimage = append(preimage, entropy[:]...)
	require.Equal(t, crypto.Hash(preimage), seed)

	otherSchemeSeed, err := derivePQKeySeed(protocol.PQSchemeFalcon512, entropy[:])
	require.NoError(t, err)
	require.NotEqual(t, seed, otherSchemeSeed)

	_, err = derivePQKeySeed(protocol.PQScheme("f"), entropy[:])
	require.ErrorIs(t, err, errPQKeyDerivation)

	_, err = derivePQKeySeed(protocol.PQSchemeFalcon1024, entropy[:len(entropy)-1])
	require.ErrorIs(t, err, errPQKeyDerivation)
}

func TestPQGenerateUsesMnemonicSizedEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rng := &countingRNG{}
	root, err := generatePQRoot(protocol.PQSchemeFalcon1024, rng)
	require.NoError(t, err)
	defer wipePQRootMaterial(&root)

	require.Equal(t, 1, rng.calls)
	require.Equal(t, pqKeyEntropySize, rng.bytes)
	require.Equal(t, protocol.PQSchemeFalcon1024, root.scheme)
	require.Equal(t, crypto.Seed{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}, root.entropy)
	require.True(t, root.public.addr.IsPQCompliant())

	signing, err := derivePQSigningMaterialFromEntropy(root.scheme, root.entropy[:])
	require.NoError(t, err)
	defer wipePQSigningMaterial(&signing)
	requirePQPublicEqual(t, root.public, signing.public)

	seed, err := derivePQKeySeed(protocol.PQSchemeFalcon1024, root.entropy[:])
	require.NoError(t, err)
	defer zeroBytes(seed[:])
	signer, err := crypto.GenerateFalconSignerFromVarLenSeed(seed[:])
	require.NoError(t, err)
	require.Equal(t, signer.PublicKey[:], root.public.pk)
	require.Equal(t, signer.PrivateKey[:], signing.private)
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
	require.NotNil(t, ops.deriveSigning)
	require.NotNil(t, ops.signTxn)

	unsupportedScheme := protocol.PQScheme("zz")
	_, err = lookupPQScheme(unsupportedScheme)
	require.ErrorIs(t, err, basics.ErrPQSchemeNotSupported)
	_, err = opsForPQScheme(unsupportedScheme)
	require.ErrorIs(t, err, basics.ErrPQSchemeNotSupported)
}

func TestPQSchemeRegistriesConsistent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for scheme, ops := range pqSchemeOpsByScheme {
		_, ok := basics.LookupPQScheme(scheme)
		require.True(t, ok, "algokey scheme %q missing from basics registry", scheme)
		require.NotNil(t, ops.deriveSigning, "scheme %q", scheme)
		require.NotNil(t, ops.signTxn, "scheme %q", scheme)
	}

	for _, scheme := range []protocol.PQScheme{protocol.PQSchemeFalcon1024} {
		_, ok := pqSchemeOpsByScheme[scheme]
		require.True(t, ok, "basics scheme %q missing from algokey ops registry", scheme)
	}
}

func TestPQPrivateRootFileStoresOnlySchemeAndEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 0)
	defer wipePQRootMaterial(&root)
	keyfile := filepath.Join(t.TempDir(), "account.pq")

	require.NoError(t, writePQRootKeyFile(keyfile, root))

	info, err := os.Stat(keyfile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	data, err := os.ReadFile(keyfile)
	require.NoError(t, err)
	require.Less(t, len(data), crypto.FalconPrivateKeySize)

	var payload pqPrivateKeyPayload
	require.NoError(t, decodePQPayload(data, pqPrivateKeyMagic, &payload))
	require.Equal(t, root.scheme, payload.Scheme)
	require.Equal(t, root.entropy[:], payload.Entropy)

	decoded, err := readPQRootKeyFile(keyfile)
	require.NoError(t, err)
	defer wipePQRootMaterial(&decoded)
	require.Equal(t, root.scheme, decoded.scheme)
	require.Equal(t, root.entropy, decoded.entropy)
	requirePQPublicEqual(t, root.public, decoded.public)

	require.ErrorIs(t, writePQRootKeyFile(keyfile, root), os.ErrExist)
}

func TestPQPrivateRootFileDoesNotPersistPublicMaterial(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 1)
	defer wipePQRootMaterial(&root)
	changed := root
	changed.public.salt++
	changed.public.addr[0] ^= 1
	changed.public.pk = append([]byte(nil), root.public.pk...)
	changed.public.pk[0] ^= 1

	require.Equal(t, encodePQPrivateKeyFileBytes(root), encodePQPrivateKeyFileBytes(changed))
}

func TestPQPublicKeyFileRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 2)
	defer wipePQRootMaterial(&root)
	pubkeyfile := filepath.Join(t.TempDir(), "account.pub.pq")

	require.NoError(t, writePQPublicKeyFile(pubkeyfile, root.public))
	decoded, err := readPQPublicKeyFile(pubkeyfile)
	require.NoError(t, err)
	requirePQPublicEqual(t, root.public, decoded)

	changed := root.public
	changed.salt++
	require.NotEqual(t, encodePQPublicKeyFileBytes(root.public), encodePQPublicKeyFileBytes(changed))
}

func TestPQKeyFileRejectsMalformedInputs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 0)
	defer wipePQRootMaterial(&root)

	var edSeed crypto.Seed
	_, err := decodePQPrivateKeyFileBytes(edSeed[:])
	require.ErrorIs(t, err, errPQKeyWrongType)

	privatePayload := pqPrivateKeyPayload{
		Scheme:  protocol.PQScheme("zz"),
		Entropy: root.entropy[:],
	}
	_, err = decodePQPrivateKeyFileBytes(encodePQPayload(pqPrivateKeyMagic, privatePayload))
	require.ErrorIs(t, err, basics.ErrPQSchemeNotSupported)

	privatePayload.Scheme = protocol.PQSchemeFalcon1024
	privatePayload.Entropy = privatePayload.Entropy[:len(privatePayload.Entropy)-1]
	_, err = decodePQPrivateKeyFileBytes(encodePQPayload(pqPrivateKeyMagic, privatePayload))
	require.ErrorIs(t, err, errPQKeyMalformed)

	publicPayload := pqPublicKeyPayload{
		Scheme:    root.public.scheme,
		Salt:      root.public.salt,
		PublicKey: root.public.pk[:len(root.public.pk)-1],
	}
	_, err = decodePQPublicKeyFileBytes(encodePQPayload(pqPublicKeyMagic, publicPayload))
	require.ErrorIs(t, err, errPQKeyMalformed)

	nonCompliant := nonCompliantPQPublic(t, root.public)
	publicPayload.PublicKey = root.public.pk
	publicPayload.Salt = nonCompliant.salt
	_, err = decodePQPublicKeyFileBytes(encodePQPayload(pqPublicKeyMagic, publicPayload))
	require.ErrorIs(t, err, errPQSaltNotCompliant)
}

func TestPQMnemonicExportImportRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 3)
	defer wipePQRootMaterial(&root)

	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	mnemonicFile := filepath.Join(tempDir, "account.mnemonic")
	importedKeyfile := filepath.Join(tempDir, "imported.pq")
	require.NoError(t, writePQRootKeyFile(keyfile, root))

	require.NoError(t, runPQExportWithOptions(keyfile, mnemonicFile))
	exportedEntropy, err := readMnemonicFile(mnemonicFile)
	require.NoError(t, err)
	defer zeroBytes(exportedEntropy[:])
	require.Equal(t, root.entropy, exportedEntropy)

	require.NoError(t, runPQImportWithOptions(mnemonicFile, importedKeyfile, protocol.PQSchemeFalcon1024))
	imported, err := readPQRootKeyFile(importedKeyfile)
	require.NoError(t, err)
	defer wipePQRootMaterial(&imported)
	require.Equal(t, root.entropy, imported.entropy)
	requirePQPublicEqual(t, root.public, imported.public)
}

func TestPQImportRejectsMalformedMnemonicFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tempDir := t.TempDir()
	mnemonicFile := filepath.Join(tempDir, "bad.mnemonic")
	importedKeyfile := filepath.Join(tempDir, "imported.pq")
	require.NoError(t, os.WriteFile(mnemonicFile, []byte("not a valid mnemonic\n"), 0600))

	err := runPQImportWithOptions(mnemonicFile, importedKeyfile, protocol.PQSchemeFalcon1024)
	require.Error(t, err)

	_, statErr := os.Stat(importedKeyfile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestPQPublicAddressSaltHandling(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 1)
	defer wipePQRootMaterial(&root)

	canonical, err := resolvePQSalt(root.public, "canonical")
	require.NoError(t, err)
	requirePQPublicEqual(t, root.public, canonical)
	require.True(t, canonical.addr.IsPQCompliant())

	nonCompliant := nonCompliantPQPublic(t, root.public)
	require.Equal(t, basics.PQAddress(root.public.scheme, nonCompliant.salt, root.public.pk), nonCompliant.addr)
	require.False(t, nonCompliant.addr.IsPQCompliant())

	_, err = resolvePQSalt(root.public, "256")
	require.ErrorContains(t, err, "invalid pq salt")
}

func TestPQSignProducesVerifiablePQEnvelope(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 0)
	defer wipePQRootMaterial(&root)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQRootKeyFile(keyfile, root))

	stxn := pqTestTxn(root.public.addr)
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
	require.Equal(t, root.public.addr, signed.Authorizer())
	require.Equal(t, root.public.scheme, signed.PQSig.Scheme)
	require.Equal(t, root.public.salt, signed.PQSig.Salt)
	require.Equal(t, root.public.pk, signed.PQSig.PublicKey)
	require.NoError(t, signed.PQSig.Verify(config.Consensus[protocol.ConsensusFuture], signed.Txn, signed.Authorizer()))

	changed := signed
	changed.Txn.Note = []byte("changed")
	require.ErrorContains(t, changed.PQSig.Verify(config.Consensus[protocol.ConsensusFuture], changed.Txn, changed.Authorizer()), "invalid falcon-1024 signature")
}

func TestPQSignSetsAndClearsAuthAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 0)
	defer wipePQRootMaterial(&root)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	require.NoError(t, writePQRootKeyFile(keyfile, root))

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
	require.Equal(t, root.public.addr, signed.AuthAddr)

	var stale basics.Address
	stale[0] = 10
	txfile = filepath.Join(tempDir, "stale.msgp")
	outfile = filepath.Join(tempDir, "stale-signed.msgp")
	stxn := pqTestTxn(root.public.addr)
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

	root := pqTestRoot(t, 0)
	defer wipePQRootMaterial(&root)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQRootKeyFile(keyfile, root))

	stxn := pqTestTxn(root.public.addr)
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

	root := pqTestRoot(t, 1)
	defer wipePQRootMaterial(&root)
	nonCompliant := nonCompliantPQPublic(t, root.public)

	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQRootKeyFile(keyfile, root))
	stxn := pqTestTxn(root.public.addr)
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	err := runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
		salt:    strconv.Itoa(int(nonCompliant.salt)),
	})
	require.ErrorIs(t, err, errPQSaltNotCompliant)
}

func TestPQMaterialDetection(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	root := pqTestRoot(t, 0)
	defer wipePQRootMaterial(&root)
	require.True(t, isPQKeyMaterial(encodePQPrivateKeyFileBytes(root)))
	require.True(t, isPQKeyMaterial(encodePQPublicKeyFileBytes(root.public)))

	var edSeed crypto.Seed
	require.False(t, isPQKeyMaterial(edSeed[:]))
}

func TestPQDecodePrivateKeyRejectsMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	_, err := decodePQPrivateKeyFileBytes([]byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
	require.ErrorIs(t, err, errPQKeyWrongType)
}
