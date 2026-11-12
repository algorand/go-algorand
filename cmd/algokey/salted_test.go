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
	"crypto/mldsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
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

func saltedTestSigning(t *testing.T, firstEntropyByte byte) saltedSigningMaterial {
	t.Helper()

	var entropy crypto.Seed
	entropy[0] = firstEntropyByte

	signing, err := deriveSaltedSigningMaterialFromEntropy(protocol.SigSchemeFalcon1024, entropy)
	require.NoError(t, err)
	return signing
}

func saltedTestTxn(sender basics.Address) transactions.SignedTxn {
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

func onCurveSaltedPublic(t *testing.T, public saltedPublicMaterial) saltedPublicMaterial {
	t.Helper()
	for i := 0; i <= 255; i++ {
		candidate := public
		candidate.Salt = basics.AddressSalt(i)
		if !candidate.address().IsOffEd25519Curve() {
			return candidate
		}
	}
	t.Fatal("expected at least one address salt that puts the address on the Ed25519 curve")
	return saltedPublicMaterial{}
}

func TestSaltedKeySeedDerivationUsesDomainSchemeAndEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	for i := range entropy {
		entropy[i] = byte(i)
	}

	seed := deriveSigSchemeKeySeed(protocol.SigSchemeFalcon1024, entropy)

	preimage := make([]byte, 0, len(protocol.PostQuantumKey)+len(protocol.SigSchemeFalcon1024)+len(entropy))
	preimage = append(preimage, string(protocol.PostQuantumKey)...)
	preimage = append(preimage, protocol.SigSchemeFalcon1024[:]...)
	preimage = append(preimage, entropy[:]...)
	require.Equal(t, crypto.Hash(preimage), seed)

	otherSchemeSeed := deriveSigSchemeKeySeed(protocol.SigSchemeFalcon512, entropy)
	require.NotEqual(t, seed, otherSchemeSeed)
}

func TestSaltedGenerateUsesMnemonicSizedEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testcases := []struct {
		name   string
		scheme protocol.SigScheme
		// address is a known answer pinning the entropy -> seed -> key -> salt
		// derivation: a change here would break existing mnemonic imports.
		address string
		// rederive regenerates the concrete signer's keys straight from the
		// scheme's keygen seed, independently of the ops registry.
		rederive func(t *testing.T, seed crypto.Digest) (publicKey, privateKey []byte)
	}{
		{
			name:    "falcon-1024",
			scheme:  protocol.SigSchemeFalcon1024,
			address: "ZEJ4BLG3XWAUUZQGCEDJLYIC6D2NCWHRSX5DJMDPE54PXXR7G3PCQTARXU",
			rederive: func(t *testing.T, seed crypto.Digest) ([]byte, []byte) {
				signer, err := crypto.GenerateFalcon1024Signer(crypto.FalconSeed(seed))
				require.NoError(t, err)
				return signer.PublicKey[:], signer.PrivateKey[:]
			},
		},
		{
			name:    "falcon-512",
			scheme:  protocol.SigSchemeFalcon512,
			address: "6XJVA45MCHLBBACBGN6ENAXFBDXCEYE5QIWA4R4LO5EY3UNAIP2UGP7ANI",
			rederive: func(t *testing.T, seed crypto.Digest) ([]byte, []byte) {
				signer, err := crypto.GenerateFalcon512Signer(crypto.FalconSeed(seed))
				require.NoError(t, err)
				return signer.PublicKey[:], signer.PrivateKey[:]
			},
		},
		{
			name:    "ed25519",
			scheme:  protocol.SigSchemeEd25519,
			address: "K7CZGXXPN6X2OXEU72FOATH333H3MR4QFSIX462VVVO7FIVTH43XHMH2G4",
			rederive: func(t *testing.T, seed crypto.Digest) ([]byte, []byte) {
				signer := crypto.GenerateSignatureSecrets(crypto.Seed(seed))
				return signer.SignatureVerifier[:], signer.SK[:]
			},
		},
		{
			name:    "ml-dsa-44",
			scheme:  protocol.SigSchemeMLDSA44,
			address: "GIWKJ6D3AE25JRHRE7HCYFDUXUFSYCSESHW2BPCOBO5DKDSP7CD5PVXHQM",
			rederive: func(t *testing.T, seed crypto.Digest) ([]byte, []byte) {
				sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed[:])
				require.NoError(t, err)
				return sk.PublicKey().Bytes(), sk.Bytes()
			},
		},
		{
			name:    "ml-dsa-65",
			scheme:  protocol.SigSchemeMLDSA65,
			address: "W5XXG73GETFRT2A5GW4VH7TE3T7LNXT7I53KPSBIIPLH4EI2T5SAYTM7UI",
			rederive: func(t *testing.T, seed crypto.Digest) ([]byte, []byte) {
				sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:])
				require.NoError(t, err)
				return sk.PublicKey().Bytes(), sk.Bytes()
			},
		},
		{
			name:    "ml-dsa-87",
			scheme:  protocol.SigSchemeMLDSA87,
			address: "QROATWTUL4TROK4QCNOAPLQSONK5WCRAEQG4ABSLRHPSAB6RBJRLF75C6I",
			rederive: func(t *testing.T, seed crypto.Digest) ([]byte, []byte) {
				sk, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed[:])
				require.NoError(t, err)
				return sk.PublicKey().Bytes(), sk.Bytes()
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rng := &countingRNG{}
			entropy, signing, err := generateSaltedSigningMaterial(tc.scheme, rng)
			require.NoError(t, err)

			require.Equal(t, 1, rng.calls)
			require.Equal(t, len(crypto.Seed{}), rng.bytes)
			require.Equal(t, tc.scheme, signing.Public.Scheme)
			require.Equal(t, crypto.Seed{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}, entropy)
			require.True(t, signing.Public.address().IsOffEd25519Curve())
			require.Equal(t, tc.address, signing.Public.address().String())

			seed := deriveSigSchemeKeySeed(tc.scheme, entropy)
			publicKey, privateKey := tc.rederive(t, seed)
			require.Equal(t, publicKey, signing.Public.PublicKey)
			require.Equal(t, privateKey, signing.PrivateKey)
		})
	}
}

func TestSigSchemeRegistriesConsistent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for scheme := range sigSchemeOpsByScheme {
		require.True(t, transactions.SigSchemeSupported(scheme), "algokey scheme %q missing from the transactions scheme table", scheme)
	}

	for _, scheme := range []protocol.SigScheme{
		protocol.SigSchemeFalcon1024, protocol.SigSchemeFalcon512, protocol.SigSchemeEd25519,
		protocol.SigSchemeMLDSA44, protocol.SigSchemeMLDSA65, protocol.SigSchemeMLDSA87,
	} {
		_, ok := sigSchemeOpsByScheme[scheme]
		require.True(t, ok, "basics scheme %q missing from algokey ops registry", scheme)
	}
}

func TestSigSchemeKeySizes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for scheme, ops := range sigSchemeOpsByScheme {
		signing, err := ops.deriveSigning(crypto.Digest{})
		require.NoError(t, err)
		require.Equal(t, ops.publicKeySize(), uint64(len(signing.Public.PublicKey)), "scheme %q", scheme)
		require.Equal(t, ops.privateKeySize(), uint64(len(signing.PrivateKey)), "scheme %q", scheme)
	}
}

func TestParseSigSchemeAcceptsLongName(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	scheme, err := parseSigScheme("falcon-1024")
	require.NoError(t, err)
	require.Equal(t, protocol.SigSchemeFalcon1024, scheme)

	scheme, err = parseSigScheme("f1")
	require.NoError(t, err)
	require.Equal(t, protocol.SigSchemeFalcon1024, scheme)

	scheme, err = parseSigScheme("falcon-512")
	require.NoError(t, err)
	require.Equal(t, protocol.SigSchemeFalcon512, scheme)

	scheme, err = parseSigScheme("f5")
	require.NoError(t, err)
	require.Equal(t, protocol.SigSchemeFalcon512, scheme)

	scheme, err = parseSigScheme("ed25519")
	require.NoError(t, err)
	require.Equal(t, protocol.SigSchemeEd25519, scheme)

	scheme, err = parseSigScheme("ed")
	require.NoError(t, err)
	require.Equal(t, protocol.SigSchemeEd25519, scheme)

	for value, want := range map[string]protocol.SigScheme{
		"ml-dsa-44": protocol.SigSchemeMLDSA44,
		"ML-DSA-44": protocol.SigSchemeMLDSA44,
		"m4":        protocol.SigSchemeMLDSA44,
		"ml-dsa-65": protocol.SigSchemeMLDSA65,
		"m6":        protocol.SigSchemeMLDSA65,
		"ml-dsa-87": protocol.SigSchemeMLDSA87,
		"m8":        protocol.SigSchemeMLDSA87,
	} {
		scheme, err = parseSigScheme(value)
		require.NoError(t, err)
		require.Equal(t, want, scheme, value)
	}
}

func TestFormatSigScheme(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, sigSchemeFalcon1024Name, formatSigScheme(protocol.SigSchemeFalcon1024))
	require.Equal(t, sigSchemeFalcon512Name, formatSigScheme(protocol.SigSchemeFalcon512))
	require.Equal(t, sigSchemeEd25519Name, formatSigScheme(protocol.SigSchemeEd25519))
	require.Equal(t, sigSchemeMLDSA44Name, formatSigScheme(protocol.SigSchemeMLDSA44))
	require.Equal(t, sigSchemeMLDSA65Name, formatSigScheme(protocol.SigSchemeMLDSA65))
	require.Equal(t, sigSchemeMLDSA87Name, formatSigScheme(protocol.SigSchemeMLDSA87))
	require.Equal(t, protocol.SigScheme{'z', 'z'}.String(), formatSigScheme(protocol.SigScheme{'z', 'z'}))
}

func TestSaltedPrivateKeyFileStoresKeysNotEntropy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	for i := range entropy {
		entropy[i] = byte(i + 1)
	}
	for scheme := range sigSchemeOpsByScheme {
		t.Run(formatSigScheme(scheme), func(t *testing.T) {
			t.Parallel()

			signing, err := deriveSaltedSigningMaterialFromEntropy(scheme, entropy)
			require.NoError(t, err)
			keyfile := filepath.Join(t.TempDir(), "account.pq")

			require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))

			info, err := os.Stat(keyfile)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0600), info.Mode().Perm())

			// The file holds the scheme's keys, never the mnemonic entropy,
			// from which every scheme's keys derive. The keygen seed is
			// specific to the scheme: an Ed25519 private key starts with it,
			// and an ML-DSA private key is the seed itself.
			data, err := os.ReadFile(keyfile)
			require.NoError(t, err)
			require.False(t, bytes.Contains(data, entropy[:]))
			seed := deriveSigSchemeKeySeed(scheme, entropy)
			switch scheme {
			case protocol.SigSchemeFalcon1024, protocol.SigSchemeFalcon512:
				require.False(t, bytes.Contains(data, seed[:]))
			default:
				require.Equal(t, seed[:], signing.PrivateKey[:len(seed)])
			}

			decoded, err := readSaltedSigningMaterial(keyfile)
			require.NoError(t, err)
			require.Equal(t, signing, decoded)
		})
	}
}

// TestSaltedMLDSAKeyFileRejectsMismatchedKeys checks that an ML-DSA key file
// whose private key does not produce its public key is rejected when read,
// not used to sign transactions that would fail verification.
func TestSaltedMLDSAKeyFileRejectsMismatchedKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, scheme := range []protocol.SigScheme{protocol.SigSchemeMLDSA44, protocol.SigSchemeMLDSA65, protocol.SigSchemeMLDSA87} {
		t.Run(formatSigScheme(scheme), func(t *testing.T) {
			t.Parallel()

			signing, err := deriveSaltedSigningMaterialFromEntropy(scheme, crypto.Seed{1})
			require.NoError(t, err)
			other, err := deriveSaltedSigningMaterialFromEntropy(scheme, crypto.Seed{2})
			require.NoError(t, err)
			_, err = decodeSaltedPrivateKeyFileBytes(protocol.Encode(&signing))
			require.NoError(t, err)

			// A corrupted private key of the right size.
			corrupted := signing
			corrupted.PrivateKey = bytes.Clone(signing.PrivateKey)
			corrupted.PrivateKey[0] ^= 1
			_, err = decodeSaltedPrivateKeyFileBytes(protocol.Encode(&corrupted))
			require.ErrorIs(t, err, errSaltedKeyMalformed)

			// Another account's valid public half.
			swapped := signing
			swapped.Public = other.Public
			_, err = decodeSaltedPrivateKeyFileBytes(protocol.Encode(&swapped))
			require.ErrorIs(t, err, errSaltedKeyMalformed)
		})
	}
}

func TestSaltedKeyFileRejectsMalformedInputs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)

	var rawSeed crypto.Seed
	_, err := decodeSaltedPrivateKeyFileBytes(rawSeed[:])
	require.ErrorIs(t, err, errSaltedKeyMalformed)

	badScheme := signing
	badScheme.Public.Scheme = protocol.SigScheme{'z', 'z'}
	_, err = decodeSaltedPrivateKeyFileBytes(protocol.Encode(&badScheme))
	require.ErrorIs(t, err, transactions.ErrSigSchemeNotSupported)

	badKey := signing
	badKey.Public.PublicKey = signing.Public.PublicKey[:len(signing.Public.PublicKey)-1]
	_, err = decodeSaltedPrivateKeyFileBytes(protocol.Encode(&badKey))
	require.ErrorIs(t, err, errSaltedKeyMalformed)

	badSK := signing
	badSK.PrivateKey = signing.PrivateKey[:len(signing.PrivateKey)-1]
	_, err = decodeSaltedPrivateKeyFileBytes(protocol.Encode(&badSK))
	require.ErrorIs(t, err, errSaltedKeyMalformed)

	tamperedSalt := signing
	tamperedSalt.Public = onCurveSaltedPublic(t, signing.Public)
	_, err = decodeSaltedPrivateKeyFileBytes(protocol.Encode(&tamperedSalt))
	require.ErrorIs(t, err, errSaltOnCurve)
}

func TestSaltedMnemonicImport(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	entropy[0] = 3
	signing, err := deriveSaltedSigningMaterialFromEntropy(protocol.SigSchemeFalcon1024, entropy)
	require.NoError(t, err)
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	importedKeyfile := filepath.Join(t.TempDir(), "imported.pq")
	require.NoError(t, runSaltedImportWithOptions(mnemonic, "falcon-1024", importedKeyfile))
	imported, err := readSaltedSigningMaterial(importedKeyfile)
	require.NoError(t, err)
	require.Equal(t, signing, imported)
}

func TestSaltedImportRejectsMalformedMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	importedKeyfile := filepath.Join(t.TempDir(), "imported.pq")
	err := runSaltedImportWithOptions("not a valid mnemonic", "falcon-1024", importedKeyfile)
	require.Error(t, err)

	_, statErr := os.Stat(importedKeyfile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestSaltedImportRejectsUnknownScheme(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	entropy[0] = 5
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	// An unknown scheme is rejected, never silently deriving a different key.
	importedKeyfile := filepath.Join(t.TempDir(), "imported.pq")
	require.ErrorIs(t, runSaltedImportWithOptions(mnemonic, "zz", importedKeyfile), transactions.ErrSigSchemeNotSupported)
	_, statErr := os.Stat(importedKeyfile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestSaltedPrintMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	entropy[0] = 6
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, printSaltedMnemonic(&out, entropy))
	require.Equal(t, "Private key mnemonic: "+mnemonic+"\nWrite these words down: they cannot be recovered from the key file.\n", out.String())
}

func TestSaltedCommandFlagShorthands(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, "S", saltedGenerateCmd.Flags().Lookup("scheme").Shorthand)
	require.Equal(t, "k", saltedGenerateCmd.Flags().Lookup("keyfile").Shorthand)

	require.Equal(t, "k", saltedInfoCmd.Flags().Lookup("keyfile").Shorthand)

	require.Equal(t, "m", saltedImportCmd.Flags().Lookup("mnemonic").Shorthand)
	require.Equal(t, "S", saltedImportCmd.Flags().Lookup("scheme").Shorthand)
	require.Equal(t, "k", saltedImportCmd.Flags().Lookup("keyfile").Shorthand)

	require.Equal(t, "k", saltedSignCmd.Flags().Lookup("keyfile").Shorthand)
	require.Equal(t, "m", saltedSignCmd.Flags().Lookup("mnemonic").Shorthand)
	require.Equal(t, "S", saltedSignCmd.Flags().Lookup("scheme").Shorthand)
	require.Equal(t, "t", saltedSignCmd.Flags().Lookup("txfile").Shorthand)
	require.Equal(t, "o", saltedSignCmd.Flags().Lookup("outfile").Shorthand)

	require.Equal(t, "k", saltedSignProgramCmd.Flags().Lookup("keyfile").Shorthand)
	require.Equal(t, "m", saltedSignProgramCmd.Flags().Lookup("mnemonic").Shorthand)
	require.Equal(t, "S", saltedSignProgramCmd.Flags().Lookup("scheme").Shorthand)
	require.Equal(t, "p", saltedSignProgramCmd.Flags().Lookup("program").Shorthand)
	require.Equal(t, "o", saltedSignProgramCmd.Flags().Lookup("outfile").Shorthand)
}

// TestSaltedCommandKeepsPQAlias checks that the name the group shipped with
// still reaches it, so scripts written against "algokey pq" keep working.
func TestSaltedCommandKeepsPQAlias(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, group := range []string{"salted", "pq"} {
		cmd, _, err := rootCmd.Find([]string{group, "generate"})
		require.NoError(t, err, group)
		require.Same(t, saltedGenerateCmd, cmd, group)
	}
}

func TestSigSchemeFlagHasNoDefault(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Empty(t, saltedGenerateCmd.Flags().Lookup("scheme").DefValue)
	require.Empty(t, saltedImportCmd.Flags().Lookup("scheme").DefValue)
	require.Empty(t, saltedSignCmd.Flags().Lookup("scheme").DefValue)
	require.Empty(t, saltedSignProgramCmd.Flags().Lookup("scheme").DefValue)
}

func TestSigSchemeMustMatchKeySource(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	_, err = resolveSaltedSigningContext("", mnemonic, "")
	require.ErrorIs(t, err, errSaltedSchemeRequired)
	require.ErrorIs(t, runSaltedImportWithOptions(mnemonic, "", filepath.Join(t.TempDir(), "imported.pq")), errSaltedSchemeRequired)

	keyfile := filepath.Join(t.TempDir(), "account.pq")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, saltedTestSigning(t, 0)))

	_, err = resolveSaltedSigningContext(keyfile, "", "falcon-1024")
	require.ErrorIs(t, err, errSaltedSchemeWithKeyfile)

	hctx, err := resolveSaltedSigningContext(keyfile, "", "")
	require.NoError(t, err)
	require.Equal(t, protocol.SigSchemeFalcon1024, hctx.signing.Public.Scheme)
}

func TestSaltedSignProducesVerifiableSaltedKeySig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, tc := range []struct {
		name   string
		scheme protocol.SigScheme
	}{
		{"falcon-1024", protocol.SigSchemeFalcon1024},
		{"falcon-512", protocol.SigSchemeFalcon512},
		{"ed25519", protocol.SigSchemeEd25519},
		{"ml-dsa-44", protocol.SigSchemeMLDSA44},
		{"ml-dsa-65", protocol.SigSchemeMLDSA65},
		{"ml-dsa-87", protocol.SigSchemeMLDSA87},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var entropy crypto.Seed
			signing, err := deriveSaltedSigningMaterialFromEntropy(tc.scheme, entropy)
			require.NoError(t, err)
			tempDir := t.TempDir()
			keyfile := filepath.Join(tempDir, "account.pq")
			txfile := filepath.Join(tempDir, "txn.msgp")
			outfile := filepath.Join(tempDir, "signed.msgp")
			require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))

			stxn := saltedTestTxn(signing.Public.address())
			require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))
			require.NoError(t, runSaltedSignWithOptions(saltedSignOptions{
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
			require.False(t, signed.SKsig.Blank())
			require.True(t, signed.AuthAddr.IsZero())
			require.Equal(t, signing.Public.address(), signed.Authorizer())
			require.Equal(t, signing.Public.Scheme, signed.SKsig.Scheme)
			require.Equal(t, signing.Public.Salt, signed.SKsig.Salt)
			require.Equal(t, signing.Public.PublicKey, signed.SKsig.PublicKey)
			require.NoError(t, signed.SKsig.Verify(config.Consensus[protocol.ConsensusFuture], signed.Txn, signed.Authorizer()))

			changed := signed
			changed.Txn.Note = []byte("changed")
			require.ErrorIs(t, changed.SKsig.Verify(config.Consensus[protocol.ConsensusFuture], changed.Txn, changed.Authorizer()), crypto.ErrSigInvalid)
		})
	}
}

func TestSaltedSignAcceptsMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	for scheme := range sigSchemeOpsByScheme {
		t.Run(formatSigScheme(scheme), func(t *testing.T) {
			t.Parallel()

			signing, err := deriveSaltedSigningMaterialFromEntropy(scheme, entropy)
			require.NoError(t, err)
			tempDir := t.TempDir()
			txfile := filepath.Join(tempDir, "txn.msgp")
			outfile := filepath.Join(tempDir, "signed.msgp")
			stxn := saltedTestTxn(signing.Public.address())
			require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

			require.NoError(t, runSaltedSignWithOptions(saltedSignOptions{
				mnemonic: mnemonic,
				scheme:   formatSigScheme(scheme),
				txfile:   txfile,
				outfile:  outfile,
			}))

			signedBytes, err := os.ReadFile(outfile)
			require.NoError(t, err)
			var signed transactions.SignedTxn
			require.NoError(t, protocol.Decode(signedBytes, &signed))
			require.Equal(t, signing.Public.PublicKey, signed.SKsig.PublicKey)
			require.NoError(t, signed.SKsig.Verify(config.Consensus[protocol.ConsensusFuture], signed.Txn, signed.Authorizer()))
		})
	}
}

func TestSaltedSignRejectsUnsupportedMnemonicScheme(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	err = runSaltedSignWithOptions(saltedSignOptions{
		mnemonic: mnemonic,
		scheme:   "zz",
		txfile:   "unsigned.msgp",
		outfile:  "signed.msgp",
	})
	require.ErrorIs(t, err, transactions.ErrSigSchemeNotSupported)
}

func TestSaltedSignRejectsEmptyInputFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "empty.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))
	require.NoError(t, os.WriteFile(txfile, nil, 0600))

	err := runSaltedSignWithOptions(saltedSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	})
	require.ErrorContains(t, err, "no transactions found")

	_, statErr := os.Stat(outfile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestSaltedSignSetsAndClearsAuthAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))

	var sender basics.Address
	sender[0] = 9
	txfile := filepath.Join(tempDir, "rekey.msgp")
	outfile := filepath.Join(tempDir, "rekey-signed.msgp")
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&transactions.SignedTxn{Txn: saltedTestTxn(sender).Txn}), 0600))
	require.NoError(t, runSaltedSignWithOptions(saltedSignOptions{
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
	stxn := saltedTestTxn(signing.Public.address())
	stxn.AuthAddr = stale
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))
	require.NoError(t, runSaltedSignWithOptions(saltedSignOptions{
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
	require.NoError(t, runSaltedSignWithOptions(saltedSignOptions{
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
	require.False(t, resigned.SKsig.Blank())
}

func TestSaltedSignRejectsMixedSignaturesUnlessOverwrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))

	stxn := saltedTestTxn(signing.Public.address())
	stxn.Sig[0] = 1
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	err := runSaltedSignWithOptions(saltedSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	})
	require.ErrorIs(t, err, errSaltedTxnAlreadySigned)

	require.NoError(t, runSaltedSignWithOptions(saltedSignOptions{
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
	require.False(t, signed.SKsig.Blank())
}

func TestSaltedSignRejectsOnCurveSalt(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// A key file tampered with a salt that puts the address on the Ed25519 curve is refused at sign.
	signing := saltedTestSigning(t, 1)
	signing.Public = onCurveSaltedPublic(t, signing.Public)

	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	txfile := filepath.Join(tempDir, "txn.msgp")
	outfile := filepath.Join(tempDir, "signed.msgp")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))
	stxn := saltedTestTxn(signing.Public.address())
	require.NoError(t, os.WriteFile(txfile, protocol.Encode(&stxn), 0600))

	err := runSaltedSignWithOptions(saltedSignOptions{
		keyfile: keyfile,
		txfile:  txfile,
		outfile: outfile,
	})
	require.ErrorIs(t, err, errSaltOnCurve)
}

func TestSaltedDecodePrivateKeyRejectsMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	_, err := decodeSaltedPrivateKeyFileBytes([]byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
	require.ErrorIs(t, err, errSaltedKeyMalformed)
}

func TestSaltedSignProgramProducesVerifiableDelegatedLogicSig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	programFile := filepath.Join(tempDir, "program.teal.tok")
	lsigFile := filepath.Join(tempDir, "program.lsig")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))

	ops, err := logic.AssembleStringWithVersion("int 1", 1)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(programFile, ops.Program, 0600))

	require.NoError(t, runSaltedSignProgramWithOptions(saltedSignProgramOptions{
		keyfile: keyfile,
		program: programFile,
		outfile: lsigFile,
	}))

	lsigBytes, err := os.ReadFile(lsigFile)
	require.NoError(t, err)
	var lsig transactions.LogicSig
	require.NoError(t, protocol.Decode(lsigBytes, &lsig))

	require.Equal(t, ops.Program, lsig.Logic)
	require.True(t, lsig.Sig.Blank())
	require.True(t, lsig.Msig.Blank())
	require.True(t, lsig.LMsig.Blank())
	require.False(t, lsig.SKsig.Blank())
	require.Equal(t, signing.Public.Scheme, lsig.SKsig.Scheme)
	require.Equal(t, signing.Public.Salt, lsig.SKsig.Salt)
	require.Equal(t, signing.Public.PublicKey, lsig.SKsig.PublicKey)

	proto := config.Consensus[protocol.ConsensusFuture]
	payload := logic.SKsigDelegatedProgram{Addr: signing.Public.address(), Program: lsig.Logic}
	require.NoError(t, lsig.SKsig.Verify(proto, payload, signing.Public.address()))

	hdr := bookkeeping.BlockHeader{UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: protocol.ConsensusFuture}}
	stxn := saltedTestTxn(signing.Public.address())
	stxn.Lsig = lsig
	_, err = verify.TxnGroup([]transactions.SignedTxn{stxn}, &hdr, nil, logic.NoHeaderLedger{})
	require.NoError(t, err)

	wrongAuthorizerTxn := stxn
	wrongAuthorizerTxn.Txn.Sender[0] ^= 1
	_, err = verify.TxnGroup([]transactions.SignedTxn{wrongAuthorizerTxn}, &hdr, nil, logic.NoHeaderLedger{})
	require.ErrorContains(t, err, "salted-key signature authorizer mismatch")
}

func TestSaltedSignProgramAcceptsMnemonic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var entropy crypto.Seed
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	ops, err := logic.AssembleStringWithVersion("int 1", 1)
	require.NoError(t, err)

	for scheme := range sigSchemeOpsByScheme {
		t.Run(formatSigScheme(scheme), func(t *testing.T) {
			t.Parallel()

			signing, err := deriveSaltedSigningMaterialFromEntropy(scheme, entropy)
			require.NoError(t, err)
			tempDir := t.TempDir()
			programFile := filepath.Join(tempDir, "program.teal.tok")
			lsigFile := filepath.Join(tempDir, "program.lsig")
			require.NoError(t, os.WriteFile(programFile, ops.Program, 0600))

			require.NoError(t, runSaltedSignProgramWithOptions(saltedSignProgramOptions{
				mnemonic: mnemonic,
				scheme:   formatSigScheme(scheme),
				program:  programFile,
				outfile:  lsigFile,
			}))

			lsigBytes, err := os.ReadFile(lsigFile)
			require.NoError(t, err)
			var lsig transactions.LogicSig
			require.NoError(t, protocol.Decode(lsigBytes, &lsig))
			require.Equal(t, signing.Public.PublicKey, lsig.SKsig.PublicKey)
			payload := logic.SKsigDelegatedProgram{Addr: signing.Public.address(), Program: lsig.Logic}
			require.NoError(t, lsig.SKsig.Verify(config.Consensus[protocol.ConsensusFuture], payload, signing.Public.address()))
		})
	}
}

func TestSaltedSignProgramRejectsMixedKeySources(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)
	var entropy crypto.Seed
	mnemonic, err := mnemonicFromSeed(entropy)
	require.NoError(t, err)

	keyfile := filepath.Join(t.TempDir(), "account.pq")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))

	err = runSaltedSignProgramWithOptions(saltedSignProgramOptions{
		keyfile:  keyfile,
		mnemonic: mnemonic,
		program:  "program.teal.tok",
		outfile:  "program.lsig",
	})
	require.ErrorContains(t, err, "cannot specify both --keyfile and --mnemonic")
}

func TestSaltedSignProgramRejectsEmptyInputFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	programFile := filepath.Join(tempDir, "empty.tok")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))
	require.NoError(t, os.WriteFile(programFile, nil, 0600))

	err := runSaltedSignProgramWithOptions(saltedSignProgramOptions{
		keyfile: keyfile,
		program: programFile,
		outfile: filepath.Join(tempDir, "empty.lsig"),
	})
	require.ErrorContains(t, err, "program is empty")
}

func TestSaltedSignProgramRejectsTealSource(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)
	tempDir := t.TempDir()
	keyfile := filepath.Join(tempDir, "account.pq")
	require.NoError(t, writeSaltedPrivateKeyFile(keyfile, signing))

	tealFile := filepath.Join(tempDir, "program.teal")
	require.NoError(t, os.WriteFile(tealFile, []byte("int 1"), 0600))
	err := runSaltedSignProgramWithOptions(saltedSignProgramOptions{
		keyfile: keyfile,
		program: tealFile,
		outfile: filepath.Join(tempDir, "program.lsig"),
	})
	require.ErrorContains(t, err, "looks like TEAL source")

	textFile := filepath.Join(tempDir, "program.tok")
	require.NoError(t, os.WriteFile(textFile, []byte("#pragma version 1\nint 1"), 0600))
	err = runSaltedSignProgramWithOptions(saltedSignProgramOptions{
		keyfile: keyfile,
		program: textFile,
		outfile: filepath.Join(tempDir, "program.lsig"),
	})
	require.ErrorContains(t, err, "not compiled bytecode")

	pragmalessFile := filepath.Join(tempDir, "pragmaless.tok")
	require.NoError(t, os.WriteFile(pragmalessFile, []byte("int 1"), 0600))
	err = runSaltedSignProgramWithOptions(saltedSignProgramOptions{
		keyfile: keyfile,
		program: pragmalessFile,
		outfile: filepath.Join(tempDir, "program.lsig"),
	})
	require.ErrorContains(t, err, "not compiled bytecode")
}

func TestSaltedCheckAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	signing := saltedTestSigning(t, 0)
	require.NoError(t, runSaltedCheckAddress(signing.Public.address().String()))

	var seed crypto.Seed
	onCurve := basics.Address(crypto.GenerateSignatureSecrets(seed).SignatureVerifier)
	require.ErrorContains(t, runSaltedCheckAddress(onCurve.String()), "on the Ed25519 curve")

	require.ErrorContains(t, runSaltedCheckAddress("not-an-address"), "cannot parse address")
}

// TestSaltedSignMLDSAIsHedged checks that algokey signs with ML-DSA's hedged
// variant: signing the same transaction twice gives two different signatures,
// both valid.
func TestSaltedSignMLDSAIsHedged(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusFuture]
	for _, scheme := range []protocol.SigScheme{protocol.SigSchemeMLDSA44, protocol.SigSchemeMLDSA65, protocol.SigSchemeMLDSA87} {
		t.Run(formatSigScheme(scheme), func(t *testing.T) {
			t.Parallel()

			signing, err := deriveSaltedSigningMaterialFromEntropy(scheme, crypto.Seed{})
			require.NoError(t, err)
			hctx := saltedSigningContext{ops: sigSchemeOpsByScheme[scheme], signing: signing}
			txn := saltedTestTxn(signing.Public.address()).Txn

			first, err := signSalted(hctx, txn)
			require.NoError(t, err)
			second, err := signSalted(hctx, txn)
			require.NoError(t, err)
			require.NotEqual(t, first.Signature, second.Signature)
			require.NoError(t, first.Verify(proto, txn, signing.Public.address()))
			require.NoError(t, second.Verify(proto, txn, signing.Public.address()))
		})
	}
}
