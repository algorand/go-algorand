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

package kmdtest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
   "github.com/algorand/go-algorand/testPartitioning"
)

func TestGenerateAndListKeys(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Request a new key
	req0 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp0 := kmdapi.APIV1POSTKeyResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Key should not be empty
	a.NotEmpty(resp0.Address)

	// List public keys
	req1 := kmdapi.APIV1POSTKeyListRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp1 := kmdapi.APIV1POSTKeyListResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// List should have exactly one entry
	a.Equal(len(resp1.Addresses), 1)

	// Only entry should equal generated public key
	a.Equal(resp1.Addresses[0], resp0.Address)

	// Generate another key
	req2 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp2 := kmdapi.APIV1POSTKeyResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	// List public keys
	req3 := kmdapi.APIV1POSTKeyListRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp3 := kmdapi.APIV1POSTKeyListResponse{}
	err = f.Client.DoV1Request(req3, &resp3)
	a.NoError(err)

	// List should have exactly two entries
	a.Equal(len(resp3.Addresses), 2)
}

func TestImportKey(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Generate a key outside of kmd
	seed := crypto.Seed{}
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)

	// Import the key
	req0 := kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: walletHandleToken,
		PrivateKey:        crypto.PrivateKey(secrets.SK),
	}
	resp0 := kmdapi.APIV1POSTKeyImportResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Public key should be that of the key we imported
	a.Equal(resp0.Address, basics.Address(secrets.SignatureVerifier).GetUserAddress())

	// Try to import the same key
	req1 := kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: walletHandleToken,
		PrivateKey:        crypto.PrivateKey(secrets.SK),
	}
	resp1 := kmdapi.APIV1POSTKeyImportResponse{}
	err = f.Client.DoV1Request(req1, &resp1)

	// Should fail (duplicate key)
	a.Error(err)

	// List public keys
	req2 := kmdapi.APIV1POSTKeyListRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp2 := kmdapi.APIV1POSTKeyListResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	// List should have exactly one entry
	a.Equal(len(resp2.Addresses), 1)

	// Only entry should equal generated public key
	a.Equal(resp2.Addresses[0], basics.Address(secrets.SignatureVerifier).GetUserAddress())
}

func TestExportKey(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Generate a key outside of kmd
	seed := crypto.Seed{}
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)

	// Import the key
	req0 := kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: walletHandleToken,
		PrivateKey:        crypto.PrivateKey(secrets.SK),
	}
	resp0 := kmdapi.APIV1POSTKeyImportResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Public key should be that of the key we imported
	a.Equal(resp0.Address, basics.Address(secrets.SignatureVerifier).GetUserAddress())

	// List public keys
	req1 := kmdapi.APIV1POSTKeyListRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp1 := kmdapi.APIV1POSTKeyListResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// List should have exactly one entry
	a.Equal(len(resp1.Addresses), 1)

	// Only entry should equal generated public key
	a.Equal(resp1.Addresses[0], basics.Address(secrets.SignatureVerifier).GetUserAddress())

	// Export the key
	req2 := kmdapi.APIV1POSTKeyExportRequest{
		WalletHandleToken: walletHandleToken,
		Address:           resp0.Address,
		WalletPassword:    f.WalletPassword,
	}
	resp2 := kmdapi.APIV1POSTKeyExportResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	// Response should be same secret key
	a.Equal(resp2.PrivateKey, crypto.PrivateKey(secrets.SK))

	// Export with wrong password should fail
	req3 := kmdapi.APIV1POSTKeyExportRequest{
		WalletHandleToken: walletHandleToken,
		Address:           resp0.Address,
		WalletPassword:    "wr0ng_p4ssw0rd",
	}
	resp3 := kmdapi.APIV1POSTKeyExportResponse{}
	err = f.Client.DoV1Request(req3, &resp3)
	a.Error(err)
}

func TestDeleteKey(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Request a new key
	req0 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp0 := kmdapi.APIV1POSTKeyResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Token should not be empty
	a.NotEqual(resp0.Address, crypto.Digest{})

	// List public keys
	req1 := kmdapi.APIV1POSTKeyListRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp1 := kmdapi.APIV1POSTKeyListResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// List should have exactly one entry
	a.Equal(len(resp1.Addresses), 1)

	// Only entry should equal generated public key
	a.Equal(resp1.Addresses[0], resp0.Address)

	// Delete with wrong password should fail
	req2 := kmdapi.APIV1DELETEKeyRequest{
		WalletHandleToken: walletHandleToken,
		Address:           resp0.Address,
		WalletPassword:    "wr0ng_p4ssw0rd",
	}
	resp2 := kmdapi.APIV1DELETEKeyResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.Error(err)

	// Try to delete the key
	req3 := kmdapi.APIV1DELETEKeyRequest{
		WalletHandleToken: walletHandleToken,
		WalletPassword:    f.WalletPassword,
		Address:           resp0.Address,
	}
	resp3 := kmdapi.APIV1DELETEKeyResponse{}
	err = f.Client.DoV1Request(req3, &resp3)
	a.NoError(err)

	// List public keys
	req4 := kmdapi.APIV1POSTKeyListRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp4 := kmdapi.APIV1POSTKeyListResponse{}
	err = f.Client.DoV1Request(req4, &resp4)
	a.NoError(err)

	// List should have exactly zero entries
	a.Equal(len(resp4.Addresses), 0)
}

func TestSignTransaction(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Generate a key outside of kmd
	seed := crypto.Seed{}
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)
	pk := crypto.Digest(secrets.SignatureVerifier)

	// Import the key
	req0 := kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: walletHandleToken,
		PrivateKey:        crypto.PrivateKey(secrets.SK),
	}
	resp0 := kmdapi.APIV1POSTKeyImportResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Make a transaction
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     basics.Address(pk),
			Fee:        basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid: basics.Round(1),
			LastValid:  basics.Round(1),
			Note:       []byte(""),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: basics.Address{},
			Amount:   basics.MicroAlgos{},
		},
	}

	// Request a signature
	req1 := kmdapi.APIV1POSTTransactionSignRequest{
		WalletHandleToken: walletHandleToken,
		Transaction:       protocol.Encode(&tx),
		WalletPassword:    f.WalletPassword,
	}
	resp1 := kmdapi.APIV1POSTTransactionSignResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// SignedTxn signature should not be empty
	var stx transactions.SignedTxn
	err = protocol.Decode(resp1.SignedTransaction, &stx)
	a.NoError(err)
	a.NotEqual(stx.Sig, crypto.Signature{})

	// TODO The SignedTxn should actually verify
	// a.NoError(stx.Verify())
}

func TestSignProgram(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Generate a key outside of kmd
	seed := crypto.Seed{}
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)
	pk := crypto.Digest(secrets.SignatureVerifier)

	// Import the key
	req0 := kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: walletHandleToken,
		PrivateKey:        crypto.PrivateKey(secrets.SK),
	}
	resp0 := kmdapi.APIV1POSTKeyImportResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	program := []byte("blah blah blah, not a real program, just some bytes to sign, kmd does not have a program interpreter to know if the program is legitimate, but it _does_ prefix the program with protocol.Program and we can verify that here below")

	addr := basics.Address(pk)

	// Request a signature
	req1 := kmdapi.APIV1POSTProgramSignRequest{
		WalletHandleToken: walletHandleToken,
		Address:           addr.String(),
		Program:           program,
		WalletPassword:    f.WalletPassword,
	}
	resp1 := kmdapi.APIV1POSTProgramSignResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// SignedTxn signature should not be empty
	a.NotEmpty(len(resp1.Signature), 0)
	var sig crypto.Signature
	copy(sig[:], resp1.Signature)
	a.NotEqual(sig, crypto.Signature{})

	ph := logic.Program(program)
	a.True(secrets.SignatureVerifier.Verify(ph, sig))
}

func BenchmarkSignTransaction(b *testing.B) {
	a := require.New(fixtures.SynchronizedTest(b))
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(b)
	defer f.Shutdown()

	// Generate a key outside of kmd
	seed := crypto.Seed{}
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)
	pk := crypto.PublicKey(secrets.SignatureVerifier)

	// Import the key
	req0 := kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: walletHandleToken,
		PrivateKey:        crypto.PrivateKey(secrets.SK),
	}
	resp0 := kmdapi.APIV1POSTKeyImportResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Make a transaction
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     basics.Address(pk),
			Fee:        basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid: basics.Round(1),
			LastValid:  basics.Round(1),
			Note:       []byte(""),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: basics.Address{},
			Amount:   basics.MicroAlgos{},
		},
	}

	b.Run("sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Request a signature
			req1 := kmdapi.APIV1POSTTransactionSignRequest{
				WalletHandleToken: walletHandleToken,
				Transaction:       protocol.Encode(&tx),
				WalletPassword:    f.WalletPassword,
			}
			resp1 := kmdapi.APIV1POSTTransactionSignResponse{}
			err = f.Client.DoV1Request(req1, &resp1)
			a.NoError(err)
		}
	})
}

func TestMasterKeyImportExport(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Generate a key
	req0 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp0 := kmdapi.APIV1POSTKeyResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Key should not be empty
	key0 := resp0.Address
	a.NotEqual(key0, crypto.Digest{})

	// Generate another key
	req1 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp1 := kmdapi.APIV1POSTKeyResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// Key should not be empty
	key1 := resp1.Address
	a.NotEqual(key1, crypto.Digest{})

	// Export master key with incorrect password should fail
	req2 := kmdapi.APIV1POSTMasterKeyExportRequest{
		WalletHandleToken: walletHandleToken,
		WalletPassword:    "wr0ng_p4ssw0rd",
	}
	resp2 := kmdapi.APIV1POSTMasterKeyExportResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.Error(err)

	// Export master key with correct password should succeed
	req3 := kmdapi.APIV1POSTMasterKeyExportRequest{
		WalletHandleToken: walletHandleToken,
		WalletPassword:    f.WalletPassword,
	}
	resp3 := kmdapi.APIV1POSTMasterKeyExportResponse{}
	err = f.Client.DoV1Request(req3, &resp3)
	a.NoError(err)

	// MDK should not be blank
	mdk0 := resp3.MasterDerivationKey
	a.NotEqual(mdk0, crypto.MasterDerivationKey{})

	// Create another wallet, don't import the MDK
	pw := "unrelated-password"
	req4 := kmdapi.APIV1POSTWalletRequest{
		WalletName:       "unrelated-wallet",
		WalletPassword:   pw,
		WalletDriverName: "sqlite",
	}
	resp4 := kmdapi.APIV1POSTWalletResponse{}
	err = f.Client.DoV1Request(req4, &resp4)
	a.NoError(err)

	// Get the new wallet ID
	unrelatedWalletID := resp4.Wallet.ID
	a.NotEmpty(unrelatedWalletID)

	// Get a wallet token
	req5 := kmdapi.APIV1POSTWalletInitRequest{
		WalletID:       unrelatedWalletID,
		WalletPassword: pw,
	}
	resp5 := kmdapi.APIV1POSTWalletInitResponse{}
	err = f.Client.DoV1Request(req5, &resp5)
	a.NoError(err)

	// Generate a key for the unrelated wallet
	req6 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: resp5.WalletHandleToken,
	}
	resp6 := kmdapi.APIV1POSTKeyResponse{}
	err = f.Client.DoV1Request(req6, &resp6)
	a.NoError(err)

	// Key should not be empty
	key2 := resp6.Address
	a.NotEqual(key2, crypto.Digest{})

	// Key should not be equal to either of the keys from the first wallet
	a.NotEqual(key2, key0)
	a.NotEqual(key2, key1)

	// Create another wallet, import the MDK
	pw = "related-password"
	req7 := kmdapi.APIV1POSTWalletRequest{
		WalletName:          "related-wallet",
		WalletPassword:      pw,
		WalletDriverName:    "sqlite",
		MasterDerivationKey: mdk0,
	}
	resp7 := kmdapi.APIV1POSTWalletResponse{}
	err = f.Client.DoV1Request(req7, &resp7)
	a.NoError(err)

	// Get the new wallet ID
	relatedWalletID := resp7.Wallet.ID
	a.NotEmpty(relatedWalletID)

	// Get a wallet token
	req8 := kmdapi.APIV1POSTWalletInitRequest{
		WalletID:       relatedWalletID,
		WalletPassword: pw,
	}
	resp8 := kmdapi.APIV1POSTWalletInitResponse{}
	err = f.Client.DoV1Request(req8, &resp8)
	a.NoError(err)

	relatedWalletHandleToken := resp8.WalletHandleToken

	// Generate a key in the new wallet
	req9 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: relatedWalletHandleToken,
	}
	resp9 := kmdapi.APIV1POSTKeyResponse{}
	err = f.Client.DoV1Request(req9, &resp9)
	a.NoError(err)

	// Key should not be empty
	key3 := resp9.Address
	a.NotEqual(key3, crypto.Digest{})

	// Generate another key
	req10 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: relatedWalletHandleToken,
	}
	resp10 := kmdapi.APIV1POSTKeyResponse{}
	err = f.Client.DoV1Request(req10, &resp10)
	a.NoError(err)

	// Key should not be empty
	key4 := resp1.Address
	a.NotEqual(key4, crypto.Digest{})

	// key3 should be the same as key0
	a.Equal(key3, key0)

	// key4 should be the same as key1
	a.Equal(key4, key1)

	// Export master key for related wallet
	req11 := kmdapi.APIV1POSTMasterKeyExportRequest{
		WalletHandleToken: relatedWalletHandleToken,
		WalletPassword:    pw,
	}
	resp11 := kmdapi.APIV1POSTMasterKeyExportResponse{}
	err = f.Client.DoV1Request(req11, &resp11)
	a.NoError(err)

	// MDK should not be blank
	mdk1 := resp11.MasterDerivationKey
	a.NotEqual(mdk1, crypto.MasterDerivationKey{})

	// MDK should be the same as the first mdk
	a.Equal(mdk0, mdk1)
}

func TestMasterKeyGeneratePastImportedKeys(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Generate some keys in the first wallet
	var addrs []string
	for i := 0; i < 3; i++ {
		req := kmdapi.APIV1POSTKeyRequest{
			WalletHandleToken: walletHandleToken,
		}
		resp := kmdapi.APIV1POSTKeyResponse{}
		err := f.Client.DoV1Request(req, &resp)
		a.NoError(err)

		// Key should not be empty
		addr := resp.Address
		a.NotEmpty(addr)
		addrs = append(addrs, addr)
	}

	// Export master key with correct password should succeed
	req0 := kmdapi.APIV1POSTMasterKeyExportRequest{
		WalletHandleToken: walletHandleToken,
		WalletPassword:    f.WalletPassword,
	}
	resp0 := kmdapi.APIV1POSTMasterKeyExportResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// MDK should not be blank
	mdk := resp0.MasterDerivationKey
	a.NotEqual(mdk, crypto.MasterDerivationKey{})

	// Create another wallet, import the MDK
	pw := "related-password"
	req1 := kmdapi.APIV1POSTWalletRequest{
		WalletName:          "related-wallet",
		WalletPassword:      pw,
		WalletDriverName:    "sqlite",
		MasterDerivationKey: mdk,
	}
	resp1 := kmdapi.APIV1POSTWalletResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// Get the new wallet ID
	relatedWalletID := resp1.Wallet.ID
	a.NotEmpty(relatedWalletID)

	// Get a wallet token
	req2 := kmdapi.APIV1POSTWalletInitRequest{
		WalletID:       relatedWalletID,
		WalletPassword: pw,
	}
	resp2 := kmdapi.APIV1POSTWalletInitResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	relatedWalletHandleToken := resp2.WalletHandleToken

	// Generate a key in the new wallet
	req3 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: relatedWalletHandleToken,
	}
	resp3 := kmdapi.APIV1POSTKeyResponse{}
	err = f.Client.DoV1Request(req3, &resp3)
	a.NoError(err)

	// Key should not be empty
	addr0 := resp3.Address
	a.NotEmpty(addr0)

	// key0 should be the same as keys[0]
	a.Equal(addr0, addrs[0])

	// Export keys[1]'s secret key from the first wallet
	req4 := kmdapi.APIV1POSTKeyExportRequest{
		WalletHandleToken: walletHandleToken,
		Address:           addrs[1],
		WalletPassword:    f.WalletPassword,
	}
	resp4 := kmdapi.APIV1POSTKeyExportResponse{}
	err = f.Client.DoV1Request(req4, &resp4)
	a.NoError(err)

	// Exported secret should not be blank
	key1Secret := resp4.PrivateKey
	a.NotEqual(key1Secret, crypto.PrivateKey{})

	// Import keys[1] into the second wallet
	req5 := kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: relatedWalletHandleToken,
		PrivateKey:        key1Secret,
	}
	resp5 := kmdapi.APIV1POSTKeyImportResponse{}
	err = f.Client.DoV1Request(req5, &resp5)
	a.NoError(err)

	// Address should be addrs[1]
	a.Equal(resp5.Address, addrs[1])

	// Generate another key in the second wallet
	req6 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: relatedWalletHandleToken,
	}
	resp6 := kmdapi.APIV1POSTKeyResponse{}
	err = f.Client.DoV1Request(req6, &resp6)
	a.NoError(err)

	// Address should not be empty
	addr1 := resp6.Address
	a.NotEmpty(addr1)

	// Address should be equal to addrs[2]
	a.Equal(addr1, addrs[2])
}
