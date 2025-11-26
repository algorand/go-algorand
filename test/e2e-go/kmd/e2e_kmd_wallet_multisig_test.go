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
	"github.com/algorand/go-algorand/test/partitiontest"
)

func addrToPK(t *testing.T, addr string) crypto.PublicKey {
	req := require.New(fixtures.SynchronizedTest(t))
	a, err := basics.UnmarshalChecksumAddress(addr)
	req.NoError(err)
	return crypto.PublicKey(a)
}

func TestMultisigImportList(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Request two new keys
	req0 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp0 := kmdapi.APIV1POSTKeyResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)
	addr0 := resp0.Address
	pk0 := addrToPK(t, addr0)

	err = f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)
	addr1 := resp0.Address
	pk1 := addrToPK(t, addr1)

	// Create a 2-of-2 multisig account from the two public keys
	req1 := kmdapi.APIV1POSTMultisigImportRequest{
		WalletHandleToken: walletHandleToken,
		Version:           1,
		Threshold:         2,
		PKs:               []crypto.PublicKey{pk0, pk1},
	}
	resp1 := kmdapi.APIV1POSTMultisigImportResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)
	addr := resp1.Address

	// List multisig addresses and make sure it's there
	req2 := kmdapi.APIV1POSTMultisigListRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp2 := kmdapi.APIV1POSTMultisigListResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	// Make sure the imported multisig address is there
	a.Equal(len(resp2.Addresses), 1)
	a.Equal(resp2.Addresses[0], addr)
}

func TestMultisigExportDelete(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Request two new keys
	req0 := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp0 := kmdapi.APIV1POSTKeyResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)
	addr0 := resp0.Address
	pk0 := addrToPK(t, addr0)

	err = f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)
	addr1 := resp0.Address
	pk1 := addrToPK(t, addr1)

	// Create a 2-of-2 multisig account from the two public keys
	req1 := kmdapi.APIV1POSTMultisigImportRequest{
		WalletHandleToken: walletHandleToken,
		Version:           1,
		Threshold:         2,
		PKs:               []crypto.PublicKey{pk0, pk1},
	}
	resp1 := kmdapi.APIV1POSTMultisigImportResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)
	addr := resp1.Address

	// Export the multisig preimage
	req2 := kmdapi.APIV1POSTMultisigExportRequest{
		WalletHandleToken: walletHandleToken,
		Address:           addr,
	}
	resp2 := kmdapi.APIV1POSTMultisigExportResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	// Make sure the exported preimage is correct
	a.Equal(req1.Version, resp2.Version)
	a.Equal(req1.Threshold, resp2.Threshold)
	a.Equal(req1.PKs, resp2.PKs)

	// Delete the multisig preimage
	req3 := kmdapi.APIV1DELETEMultisigRequest{
		WalletHandleToken: walletHandleToken,
		Address:           addr,
		WalletPassword:    f.WalletPassword,
	}
	resp3 := kmdapi.APIV1DELETEMultisigResponse{}
	err = f.Client.DoV1Request(req3, &resp3)
	a.NoError(err)

	// List multisig addresses and make sure it's empty
	req4 := kmdapi.APIV1POSTMultisigListRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp4 := kmdapi.APIV1POSTMultisigListResponse{}
	err = f.Client.DoV1Request(req4, &resp4)
	a.NoError(err)

	// Make sure the imported multisig address is gone
	a.Equal(len(resp4.Addresses), 0)
}

func TestMultisigSign(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	resp, err := f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pk1 := addrToPK(t, resp.Address)
	resp, err = f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pk2 := addrToPK(t, resp.Address)
	pk3 := crypto.PublicKey{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // some public key we haven't imported

	// Create a 2-of-3 multisig account from the three public keys
	resp1, err := f.Client.ImportMultisigAddr([]byte(walletHandleToken), 1, 2, []crypto.PublicKey{pk1, pk2, pk3})

	a.NoError(err)
	msigAddr := addrToPK(t, resp1.Address)

	// Make a transaction spending from the multisig address
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     basics.Address(msigAddr),
			Fee:        basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid: basics.Round(1),
			LastValid:  basics.Round(1),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: basics.Address{},
			Amount:   basics.MicroAlgos{},
		},
	}

	// Try to sign
	req2 := kmdapi.APIV1POSTMultisigTransactionSignRequest{
		WalletHandleToken: walletHandleToken,
		Transaction:       protocol.Encode(&tx),
		PublicKey:         pk1,
		PartialMsig:       crypto.MultisigSig{},
		WalletPassword:    f.WalletPassword,
	}
	resp2 := kmdapi.APIV1POSTMultisigTransactionSignResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	var msig crypto.MultisigSig
	err = protocol.Decode(resp2.Multisig, &msig)
	a.NoError(err)

	// Try to add another signature
	req3 := kmdapi.APIV1POSTMultisigTransactionSignRequest{
		WalletHandleToken: walletHandleToken,
		Transaction:       protocol.Encode(&tx),
		PublicKey:         pk2,
		PartialMsig:       msig,
		WalletPassword:    f.WalletPassword,
	}
	resp3 := kmdapi.APIV1POSTMultisigTransactionSignResponse{}
	err = f.Client.DoV1Request(req3, &resp3)
	a.NoError(err)

	// Assemble them into a signed transaction and see if it verifies
	_, err = transactions.AssembleSignedTxn(tx, crypto.Signature{}, msig)
	a.NoError(err)

	// TODO See if the signature verifies
	// err = stxn.Verify()
	// a.NoError(err)
}

func TestMultisigSignWithSigner(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	resp, err := f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pk1 := addrToPK(t, resp.Address)
	resp, err = f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pk2 := addrToPK(t, resp.Address)
	pk3 := crypto.PublicKey{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // some public key we haven't imported

	sender, err := f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pkSender := addrToPK(t, sender.Address)

	// Create a 2-of-3 multisig account from the three public keys
	resp1, err := f.Client.ImportMultisigAddr([]byte(walletHandleToken), 1, 2, []crypto.PublicKey{pk1, pk2, pk3})

	a.NoError(err)
	msigAddr := addrToPK(t, resp1.Address)

	// Make a transaction spending from the multisig address
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     basics.Address(pkSender),
			Fee:        basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid: basics.Round(1),
			LastValid:  basics.Round(1),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: basics.Address{},
			Amount:   basics.MicroAlgos{},
		},
	}

	// Try to sign
	req2 := kmdapi.APIV1POSTMultisigTransactionSignRequest{
		WalletHandleToken: walletHandleToken,
		Transaction:       protocol.Encode(&tx),
		PublicKey:         pk1,
		PartialMsig: crypto.MultisigSig{
			Threshold: 2,
			Version:   1,
			Subsigs:   []crypto.MultisigSubsig{{Key: pk1}, {Key: pk2}, {Key: pk3}},
		},
		WalletPassword: f.WalletPassword,
		AuthAddr:       crypto.Digest(msigAddr),
	}
	resp2 := kmdapi.APIV1POSTMultisigTransactionSignResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	var msig crypto.MultisigSig
	err = protocol.Decode(resp2.Multisig, &msig)
	a.NoError(err)

	// Try to add another signature
	req3 := kmdapi.APIV1POSTMultisigTransactionSignRequest{
		WalletHandleToken: walletHandleToken,
		Transaction:       protocol.Encode(&tx),
		PublicKey:         pk2,
		PartialMsig:       msig,
		WalletPassword:    f.WalletPassword,
		AuthAddr:          crypto.Digest(msigAddr),
	}
	resp3 := kmdapi.APIV1POSTMultisigTransactionSignResponse{}
	err = f.Client.DoV1Request(req3, &resp3)
	a.NoError(err)

	// Assemble them into a signed transaction and see if it verifies
	_, err = transactions.AssembleSignedTxn(tx, crypto.Signature{}, msig)
	a.NoError(err)

}

func TestMultisigSignWithWrongSigner(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	resp, err := f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pk1 := addrToPK(t, resp.Address)
	resp, err = f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pk2 := addrToPK(t, resp.Address)
	pk3 := crypto.PublicKey{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // some public key we haven't imported

	sender, err := f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pkSender := addrToPK(t, sender.Address)

	// Create a 2-of-3 multisig account from the three public keys
	_, err = f.Client.ImportMultisigAddr([]byte(walletHandleToken), 1, 2, []crypto.PublicKey{pk1, pk2, pk3})
	a.NoError(err)

	// Make a transaction spending from the multisig address
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     basics.Address(pkSender),
			Fee:        basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid: basics.Round(1),
			LastValid:  basics.Round(1),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: basics.Address{},
			Amount:   basics.MicroAlgos{},
		},
	}

	// Try to sign
	req2 := kmdapi.APIV1POSTMultisigTransactionSignRequest{
		WalletHandleToken: walletHandleToken,
		Transaction:       protocol.Encode(&tx),
		PublicKey:         pk1,
		PartialMsig: crypto.MultisigSig{
			Threshold: 2,
			Version:   1,
			Subsigs:   []crypto.MultisigSubsig{{Key: pk1}, {Key: pk2}, {Key: pk3}},
		},
		WalletPassword: f.WalletPassword,
	}

	resp2 := kmdapi.APIV1POSTMultisigTransactionSignResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.Error(err)

}

func TestMultisigSignProgram(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	resp, err := f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pk1 := addrToPK(t, resp.Address)
	resp, err = f.Client.GenerateKey([]byte(walletHandleToken))
	a.NoError(err)
	pk2 := addrToPK(t, resp.Address)
	pk3 := crypto.PublicKey{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // some public key we haven't imported

	// Create a 2-of-3 multisig account from the three public keys
	resp1, err := f.Client.ImportMultisigAddr([]byte(walletHandleToken), 1, 2, []crypto.PublicKey{pk1, pk2, pk3})

	a.NoError(err)
	msigAddr := addrToPK(t, resp1.Address)

	program := []byte("blah blah blah, not a real program, just some bytes to sign, kmd does not have a program interpreter to know if the program is legitimate, but it _does_ prefix the program with protocol.Program and we can verify that here below")

	testMultisigSign := func(t *testing.T, useLegacyMsig bool) {
		// Try to sign
		req2 := kmdapi.APIV1POSTMultisigProgramSignRequest{
			WalletHandleToken: walletHandleToken,
			Program:           program,
			Address:           basics.Address(msigAddr).String(),
			PublicKey:         pk1,
			PartialMsig:       crypto.MultisigSig{},
			WalletPassword:    f.WalletPassword,
			UseLegacyMsig:     useLegacyMsig,
		}
		resp2 := kmdapi.APIV1POSTMultisigProgramSignResponse{}
		err = f.Client.DoV1Request(req2, &resp2)
		a.NoError(err)

		var msig crypto.MultisigSig
		err = protocol.Decode(resp2.Multisig, &msig)
		a.NoError(err)

		// Try to add another signature
		req3 := kmdapi.APIV1POSTMultisigProgramSignRequest{
			WalletHandleToken: walletHandleToken,
			Program:           program,
			Address:           basics.Address(msigAddr).String(),
			PublicKey:         pk2,
			PartialMsig:       msig,
			WalletPassword:    f.WalletPassword,
			UseLegacyMsig:     useLegacyMsig,
		}
		resp3 := kmdapi.APIV1POSTMultisigProgramSignResponse{}
		err = f.Client.DoV1Request(req3, &resp3)
		a.NoError(err)

		err = protocol.Decode(resp3.Multisig, &msig)
		a.NoError(err)

		var prog, wrongProg crypto.Hashable
		if useLegacyMsig {
			prog = logic.Program(program)
			wrongProg = logic.MultisigProgram{Addr: crypto.Digest(msigAddr), Program: program}
		} else {
			prog = logic.MultisigProgram{Addr: crypto.Digest(msigAddr), Program: program}
			wrongProg = logic.Program(program)
		}
		err = crypto.MultisigVerify(prog, crypto.Digest(msigAddr), msig)
		a.NoError(err)
		err = crypto.MultisigVerify(wrongProg, crypto.Digest(msigAddr), msig)
		a.ErrorContains(err, "At least one signature didn't pass verification")
	}

	t.Run("LegacyMsig", func(t *testing.T) { testMultisigSign(t, true) })
	t.Run("NewLMsig", func(t *testing.T) { testMultisigSign(t, false) })
}
