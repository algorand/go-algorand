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
	"os"
	"path/filepath"
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

func pqTestSigning(t *testing.T, firstEntropyByte byte) pqSigningMaterial {
	t.Helper()

	var entropy crypto.Seed
	entropy[0] = firstEntropyByte

	signing, err := derivePQSigningMaterialFromEntropy(protocol.PQSchemeFalcon1024, entropy)
	require.NoError(t, err)
	return signing
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

func nonCompliantPQPublic(t *testing.T, public pqPublicMaterial) pqPublicMaterial {
	t.Helper()
	for i := 0; i <= 255; i++ {
		candidate := public
		candidate.Salt = basics.PQAddressSalt(i)
		if !candidate.address().IsPQCompliant() {
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

	seed := derivePQKeySeed(protocol.PQSchemeFalcon1024, entropy)

	preimage := make([]byte, 0, len(protocol.PostQuantumKey)+len(protocol.PQSchemeFalcon1024)+len(entropy))
	preimage = append(preimage, string(protocol.PostQuantumKey)...)
	preimage = append(preimage, protocol.PQSchemeFalcon1024[:]...)
	preimage = append(preimage, entropy[:]...)
	require.Equal(t, crypto.Hash(preimage), seed)

	otherSchemeSeed := derivePQKeySeed(protocol.PQSchemeFalcon512, entropy)
	require.NotEqual(t, seed, otherSchemeSeed)
}

func TestPQGenerateUsesMnemonicSizedEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rng := &countingRNG{}
	entropy, signing, err := generatePQSigningMaterial(protocol.PQSchemeFalcon1024, rng)
	require.NoError(t, err)

	require.Equal(t, 1, rng.calls)
	require.Equal(t, len(crypto.Seed{}), rng.bytes)
	require.Equal(t, protocol.PQSchemeFalcon1024, signing.Public.Scheme)
	require.Equal(t, crypto.Seed{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}, entropy)
	require.True(t, signing.Public.address().IsPQCompliant())
	require.Equal(t, "ZEJ4BLG3XWAUUZQGCEDJLYIC6D2NCWHRSX5DJMDPE54PXXR7G3PCQTARXU", signing.Public.address().String())

	seed := derivePQKeySeed(protocol.PQSchemeFalcon1024, entropy)
	signer, err := crypto.GenerateFalconSigner(crypto.FalconSeed(seed))
	require.NoError(t, err)
	require.Equal(t, signer.PublicKey[:], signing.Public.PublicKey)
	require.Equal(t, signer.PrivateKey[:], signing.PrivateKey)
}

func TestPQSchemeRegistriesConsistent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for scheme := range pqSchemeOpsByScheme {
		_, ok := crypto.LookupPQScheme(scheme)
		require.True(t, ok, "algokey scheme %q missing from crypto registry", scheme)
	}

	for _, scheme := range []protocol.PQScheme{protocol.PQSchemeFalcon1024} {
		_, ok := pqSchemeOpsByScheme[scheme]
		require.True(t, ok, "basics scheme %q missing from algokey ops registry", scheme)
	}
}

func TestPQSchemeKeysFitBounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for scheme, ops := range pqSchemeOpsByScheme {
		signing, err := ops.deriveSigning(crypto.Digest{})
		require.NoError(t, err)
		require.LessOrEqual(t, len(signing.PrivateKey), maxPQPrivateKeySize, "scheme %q", scheme)
		require.Equal(t, ops.publicKeySize(), uint64(len(signing.Public.PublicKey)), "scheme %q", scheme)
	}
}

func TestParsePQSchemeAcceptsLongName(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	scheme, err := parsePQScheme("falcon-1024")
	require.NoError(t, err)
	require.Equal(t, protocol.PQSchemeFalcon1024, scheme)

	scheme, err = parsePQScheme("f1")
	require.NoError(t, err)
	require.Equal(t, protocol.PQSchemeFalcon1024, scheme)
}

func TestPQPrivateKeyFileStoresKeysNotEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	for i := range entropy {
		entropy[i] = byte(i + 1)
	}
	signing, err := derivePQSigningMaterialFromEntropy(protocol.PQSchemeFalcon1024, entropy)
	require.NoError(t, err)
	keyfile := filepath.Join(t.TempDir(), "account.pq")

	require.NoError(t, writePQPrivateKeyFile(keyfile, signing))

	info, err := os.Stat(keyfile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// The file holds the scheme's keys — never the mnemonic entropy or the
	// derived keygen seed, which would compromise keys of other schemes.
	data, err := os.ReadFile(keyfile)
	require.NoError(t, err)
	require.False(t, bytes.Contains(data, entropy[:]))
	seed := derivePQKeySeed(protocol.PQSchemeFalcon1024, entropy)
	require.False(t, bytes.Contains(data, seed[:]))

	decoded, err := readPQSigningMaterial(keyfile)
	require.NoError(t, err)
	require.Equal(t, signing, decoded)

	// info-style reads accept the private file too.
	public, err := readPQKeyFilePublic(keyfile)
	require.NoError(t, err)
	require.Equal(t, signing.Public, public)
}

func TestPQPublicKeyFileRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := pqTestSigning(t, 2)
	pubkeyfile := filepath.Join(t.TempDir(), "account.pub.pq")

	require.NoError(t, writePQPublicKeyFile(pubkeyfile, signing.Public))
	decoded, err := readPQKeyFilePublic(pubkeyfile)
	require.NoError(t, err)
	require.Equal(t, signing.Public, decoded)

	changed := signing.Public
	changed.Salt++
	require.NotEqual(t, protocol.Encode(&signing.Public), protocol.Encode(&changed))
}

func TestPQKeyFileRejectsMalformedInputs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := pqTestSigning(t, 0)

	var edSeed crypto.Seed
	_, err := decodePQPrivateKeyFileBytes(edSeed[:])
	require.ErrorIs(t, err, errPQKeyMalformed)

	badScheme := signing
	badScheme.Public.Scheme = protocol.PQScheme{'z', 'z'}
	_, err = decodePQPrivateKeyFileBytes(protocol.Encode(&badScheme))
	require.ErrorIs(t, err, crypto.ErrPQSchemeNotSupported)

	badKey := signing
	badKey.Public.PublicKey = signing.Public.PublicKey[:len(signing.Public.PublicKey)-1]
	_, err = decodePQPrivateKeyFileBytes(protocol.Encode(&badKey))
	require.ErrorIs(t, err, errPQKeyMalformed)

	publicPayload := pqPublicMaterial{
		Scheme:    signing.Public.Scheme,
		Salt:      signing.Public.Salt,
		PublicKey: signing.Public.PublicKey[:len(signing.Public.PublicKey)-1],
	}
	_, err = decodePQPublicKeyFileBytes(protocol.Encode(&publicPayload))
	require.ErrorIs(t, err, errPQKeyMalformed)

	nonCompliant := nonCompliantPQPublic(t, signing.Public)
	publicPayload.PublicKey = signing.Public.PublicKey
	publicPayload.Salt = nonCompliant.Salt
	_, err = decodePQPublicKeyFileBytes(protocol.Encode(&publicPayload))
	require.ErrorIs(t, err, errPQSaltNotCompliant)
}

func TestPQMnemonicImport(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	entropy[0] = 3
	signing, err := derivePQSigningMaterialFromEntropy(protocol.PQSchemeFalcon1024, entropy)
	require.NoError(t, err)
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	importedKeyfile := filepath.Join(t.TempDir(), "imported.pq")
	require.NoError(t, runPQImportWithOptions(mnemonic, "falcon-1024", importedKeyfile))
	imported, err := readPQSigningMaterial(importedKeyfile)
	require.NoError(t, err)
	require.Equal(t, signing, imported)
}

func TestPQImportRejectsMalformedMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	importedKeyfile := filepath.Join(t.TempDir(), "imported.pq")
	err := runPQImportWithOptions("not a valid mnemonic", "falcon-1024", importedKeyfile)
	require.Error(t, err)

	_, statErr := os.Stat(importedKeyfile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestPQImportRejectsUnknownScheme(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	entropy[0] = 5
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	// An unknown scheme is rejected, never silently deriving a different key.
	importedKeyfile := filepath.Join(t.TempDir(), "imported.pq")
	require.ErrorIs(t, runPQImportWithOptions(mnemonic, "zz", importedKeyfile), crypto.ErrPQSchemeNotSupported)
	_, statErr := os.Stat(importedKeyfile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestPQPrintMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	entropy[0] = 6
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, printPQMnemonic(&out, entropy))
	require.Equal(t, "PQ private key mnemonic: "+mnemonic+"\nWrite these words down: they cannot be recovered from the key file.\n", out.String())
}

func TestPQCommandFlagShorthands(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, "S", pqGenerateCmd.Flags().Lookup("scheme").Shorthand)
	require.Equal(t, "f", pqGenerateCmd.Flags().Lookup("keyfile").Shorthand)
	require.Equal(t, "p", pqGenerateCmd.Flags().Lookup("pubkeyfile").Shorthand)

	require.Equal(t, "f", pqInfoCmd.Flags().Lookup("keyfile").Shorthand)

	require.Equal(t, "m", pqImportCmd.Flags().Lookup("mnemonic").Shorthand)
	require.Equal(t, "S", pqImportCmd.Flags().Lookup("scheme").Shorthand)
	require.Equal(t, "f", pqImportCmd.Flags().Lookup("keyfile").Shorthand)

	require.Equal(t, "k", pqSignCmd.Flags().Lookup("keyfile").Shorthand)
	require.Equal(t, "m", pqSignCmd.Flags().Lookup("mnemonic").Shorthand)
	require.Equal(t, "S", pqSignCmd.Flags().Lookup("scheme").Shorthand)
	require.Equal(t, "t", pqSignCmd.Flags().Lookup("txfile").Shorthand)
	require.Equal(t, "o", pqSignCmd.Flags().Lookup("outfile").Shorthand)
}

func TestPQSignProducesVerifiablePQEnvelope(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := pqTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQPrivateKeyFile(keyfile, signing))

	stxn := pqTestTxn(signing.Public.address())
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	}))

	signedBytes, err := os.ReadFile(outfile)
	require.NoError(t, err)
	var signed transactions.SignedTxn
	require.NoError(t, protocol.Decode(signedBytes, &signed))

	require.True(t, signed.Sig.Blank())
	require.True(t, signed.Msig.Blank())
	require.True(t, signed.Lsig.Blank())
	require.False(t, signed.PQsig.Blank())
	require.True(t, signed.AuthAddr.IsZero())
	require.Equal(t, signing.Public.address(), signed.Authorizer())
	require.Equal(t, signing.Public.Scheme, signed.PQsig.Scheme)
	require.Equal(t, signing.Public.Salt, signed.PQsig.Salt)
	require.Equal(t, signing.Public.PublicKey, signed.PQsig.PublicKey)
	require.NoError(t, signed.PQsig.Verify(config.Consensus[protocol.ConsensusFuture], signed.Txn, signed.Authorizer()))

	changed := signed
	changed.Txn.Note = []byte("changed")
	require.ErrorContains(t, changed.PQsig.Verify(config.Consensus[protocol.ConsensusFuture], changed.Txn, changed.Authorizer()), "invalid falcon-1024 signature")
}

func TestPQSignAcceptsMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := pqTestSigning(t, 0)
	var entropy crypto.Seed
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	tempDir := t.TempDir()
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	stxn := pqTestTxn(signing.Public.address())
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		mnemonic: mnemonic,
		scheme:   "f1",
		txfile:   txfile,
		outfile:  outfile,
	}))

	signedBytes, err := os.ReadFile(outfile)
	require.NoError(t, err)
	var signed transactions.SignedTxn
	require.NoError(t, protocol.Decode(signedBytes, &signed))
	require.Equal(t, signing.Public.PublicKey, signed.PQsig.PublicKey)
	require.NoError(t, signed.PQsig.Verify(config.Consensus[protocol.ConsensusFuture], signed.Txn, signed.Authorizer()))
}

func TestPQSignRejectsUnsupportedMnemonicScheme(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	err = runPQSignWithOptions(pqSignOptions{
		mnemonic: mnemonic,
		scheme:   "zz",
		txfile:   "unsigned.msgp",
		outfile:  "signed.msgp",
	})
	require.ErrorIs(t, err, crypto.ErrPQSchemeNotSupported)
}

func TestPQSignRejectsEmptyInputFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := pqTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "empty.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQPrivateKeyFile(keyfile, signing))
	require.NoError(t, os.WriteFile(txfile, nil, 0600))

	err := runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	})
	require.ErrorContains(t, err, "no transactions found")

	_, statErr := os.Stat(outfile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestPQSignSetsAndClearsAuthAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := pqTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	require.NoError(t, writePQPrivateKeyFile(keyfile, signing))

	var sender basics.Address
	sender[0] = 9
	txfile := filepath.Join(tempDir, "rekey.msgp")
	outfile := filepath.Join(tempDir, "rekey-signed.msgp")
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&transactions.SignedTxn{Txn: pqTestTxn(sender).Txn}), 0600))
	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	}))
	var signed transactions.SignedTxn
	data, err := os.ReadFile(outfile)
	require.NoError(t, err)
	require.NoError(t, protocol.Decode(data, &signed))
	require.Equal(t, signing.Public.address(), signed.AuthAddr)

	var stale basics.Address
	stale[0] = 10
	txfile = filepath.Join(tempDir, "stale.msgp")
	outfile = filepath.Join(tempDir, "stale-signed.msgp")
	stxn := pqTestTxn(signing.Public.address())
	stxn.AuthAddr = stale
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))
	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	}))
	data, err = os.ReadFile(outfile)
	require.NoError(t, err)
	var staleSigned transactions.SignedTxn
	require.NoError(t, protocol.Decode(data, &staleSigned))
	require.Equal(t, stale, staleSigned.AuthAddr)

	// Overwriting clears the previous authorization, including AuthAddr.
	resignedOutfile := filepath.Join(tempDir, "stale-resigned.msgp")
	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile:   keyfile,
		txfile:    outfile,
		outfile:   resignedOutfile,
		overwrite: true,
	}))
	data, err = os.ReadFile(resignedOutfile)
	require.NoError(t, err)
	var resigned transactions.SignedTxn
	require.NoError(t, protocol.Decode(data, &resigned))
	require.True(t, resigned.AuthAddr.IsZero())
	require.False(t, resigned.PQsig.Blank())
}

func TestPQSignRejectsMixedSignaturesUnlessOverwrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := pqTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQPrivateKeyFile(keyfile, signing))

	stxn := pqTestTxn(signing.Public.address())
	stxn.Sig[0] = 1
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	err := runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	})
	require.ErrorIs(t, err, errPQTxnAlreadySigned)

	require.NoError(t, runPQSignWithOptions(pqSignOptions{
		keyfile:   keyfile,
		txfile:    txfile,
		outfile:   outfile,
		overwrite: true,
	}))
	data, err := os.ReadFile(outfile)
	require.NoError(t, err)
	var signed transactions.SignedTxn
	require.NoError(t, protocol.Decode(data, &signed))
	require.True(t, signed.Sig.Blank())
	require.False(t, signed.PQsig.Blank())
}

func TestPQSignRejectsNonCompliantSalt(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// A key file tampered with a non-compliant salt is refused at sign.
	signing := pqTestSigning(t, 1)
	signing.Public = nonCompliantPQPublic(t, signing.Public)

	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writePQPrivateKeyFile(keyfile, signing))
	stxn := pqTestTxn(signing.Public.address())
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	err := runPQSignWithOptions(pqSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	})
	require.ErrorIs(t, err, errPQSaltNotCompliant)
}

func TestPQKeyFileKindsAreDisjoint(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := pqTestSigning(t, 0)

	// Decoding a file as the wrong kind fails (field sets are disjoint and
	// decoding rejects unknown fields); readPQKeyFilePublic relies on this.
	_, err := decodePQPrivateKeyFileBytes(protocol.Encode(&signing.Public))
	require.ErrorIs(t, err, errPQKeyMalformed)
	_, err = decodePQPublicKeyFileBytes(protocol.Encode(&signing))
	require.ErrorIs(t, err, errPQKeyMalformed)
}

func TestPQDecodePrivateKeyRejectsMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	_, err := decodePQPrivateKeyFileBytes([]byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
	require.ErrorIs(t, err, errPQKeyMalformed)
}
