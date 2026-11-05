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

package v1

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/daemon/kmd/session"
	"github.com/algorand/go-algorand/daemon/kmd/wallet"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const testToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testPrefix = "/v1"
const testPassword = "testpassword"

// mockWallet implements wallet.Wallet for testing handlers without a real
// wallet driver or filesystem.
type mockWallet struct {
	metadata wallet.Metadata

	// Return values for operations
	keys          []crypto.Digest
	generatedAddr crypto.Digest
	importedAddr  crypto.Digest
	exportedKey   crypto.PrivateKey
	signedTx      []byte
	signedProgram []byte

	multisigAddrs   []crypto.Digest
	multisigAddr    crypto.Digest
	multisigVersion uint8
	multisigThresh  uint8
	multisigPKs     []crypto.PublicKey
	multisigSig     crypto.MultisigSig

	masterKey crypto.MasterDerivationKey

	// Error to return (nil = success)
	err error

	// Arguments received by the most recent operation, so tests can check
	// that handlers forward request fields to the wallet unchanged
	gotPassword  []byte
	gotPK        crypto.PublicKey
	gotAddr      crypto.Digest
	gotTx        transactions.Transaction
	gotProgram   []byte
	gotPartial   crypto.MultisigSig
	gotLegacy    bool
	gotSK        crypto.PrivateKey
	gotVersion   uint8
	gotThreshold uint8
	gotPKs       []crypto.PublicKey
}

func (m *mockWallet) Init(pw []byte) error               { return m.err }
func (m *mockWallet) CheckPassword(pw []byte) error      { return m.err }
func (m *mockWallet) Metadata() (wallet.Metadata, error) { return m.metadata, m.err }
func (m *mockWallet) ListKeys() ([]crypto.Digest, error) { return m.keys, m.err }
func (m *mockWallet) GenerateKey(bool) (crypto.Digest, error) {
	return m.generatedAddr, m.err
}

func (m *mockWallet) ImportKey(sk crypto.PrivateKey) (crypto.Digest, error) {
	m.gotSK = sk
	return m.importedAddr, m.err
}

func (m *mockWallet) ExportKey(pk crypto.Digest, pw []byte) (crypto.PrivateKey, error) {
	m.gotAddr, m.gotPassword = pk, pw
	return m.exportedKey, m.err
}

func (m *mockWallet) DeleteKey(pk crypto.Digest, pw []byte) error {
	m.gotAddr, m.gotPassword = pk, pw
	return m.err
}

func (m *mockWallet) ExportMasterDerivationKey(pw []byte) (crypto.MasterDerivationKey, error) {
	m.gotPassword = pw
	return m.masterKey, m.err
}

func (m *mockWallet) ImportMultisigAddr(version, threshold uint8, pks []crypto.PublicKey) (crypto.Digest, error) {
	m.gotVersion, m.gotThreshold, m.gotPKs = version, threshold, pks
	return m.multisigAddr, m.err
}

func (m *mockWallet) LookupMultisigPreimage(addr crypto.Digest) (uint8, uint8, []crypto.PublicKey, error) {
	return m.multisigVersion, m.multisigThresh, m.multisigPKs, m.err
}

func (m *mockWallet) ListMultisigAddrs() ([]crypto.Digest, error) {
	return m.multisigAddrs, m.err
}
func (m *mockWallet) DeleteMultisigAddr(addr crypto.Digest, pw []byte) error {
	m.gotAddr, m.gotPassword = addr, pw
	return m.err
}

func (m *mockWallet) SignTransaction(tx transactions.Transaction, pk crypto.PublicKey, pw []byte) ([]byte, error) {
	m.gotTx, m.gotPK, m.gotPassword = tx, pk, pw
	return m.signedTx, m.err
}

func (m *mockWallet) MultisigSignTransaction(tx transactions.Transaction, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte, signer crypto.Digest) (crypto.MultisigSig, error) {
	m.gotTx, m.gotPK, m.gotPartial, m.gotPassword, m.gotAddr = tx, pk, partial, pw, signer
	return m.multisigSig, m.err
}

func (m *mockWallet) SignProgram(program []byte, src crypto.Digest, pw []byte) ([]byte, error) {
	m.gotProgram, m.gotAddr, m.gotPassword = program, src, pw
	return m.signedProgram, m.err
}

func (m *mockWallet) MultisigSignProgram(program []byte, src crypto.Digest, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte, useLegacyMsig bool) (crypto.MultisigSig, error) {
	m.gotProgram, m.gotAddr, m.gotPK, m.gotPartial, m.gotPassword, m.gotLegacy = program, src, pk, partial, pw, useLegacyMsig
	return m.multisigSig, m.err
}

// testHarness bundles a handler, session manager, and test wallet for use in tests.
type testHarness struct {
	handler http.Handler
	sm      *session.Manager
	wallet  *mockWallet
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	cfg := config.KMDConfig{SessionLifetimeSecs: 60}
	sm := session.MakeManager(cfg)
	t.Cleanup(func() { sm.Kill() })

	mux := http.NewServeMux()
	log := logging.TestingLog(t)
	RegisterHandlers(mux, testPrefix, sm, log, testToken, func() {})

	w := &mockWallet{
		metadata: wallet.Metadata{
			ID:         []byte("test-wallet-id"),
			Name:       []byte("test-wallet"),
			DriverName: "mock",
		},
	}

	return &testHarness{handler: mux, sm: sm, wallet: w}
}

// initSession initializes a wallet handle in the session manager and returns
// the handle token.
func (h *testHarness) initSession(t *testing.T) string {
	t.Helper()
	token, err := h.sm.InitWalletHandle(h.wallet, []byte(testPassword))
	require.NoError(t, err)
	return string(token)
}

func authedRequest(method, path string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		buf.Write(protocol.EncodeJSON(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("X-KMD-API-Token", testToken)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func decodeResponse(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	require.NoError(t, protocol.DecodeJSON(rr.Body.Bytes(), v))
}

// --- Wallet session tests ---

func TestWalletInfoHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/wallet/info", kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: handleToken,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTWalletInfoResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal("test-wallet-id", resp.WalletHandle.Wallet.ID)
	a.Equal("test-wallet", resp.WalletHandle.Wallet.Name)
	a.Greater(resp.WalletHandle.ExpiresSeconds, int64(0))
}

func TestWalletRenewHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/wallet/renew", kmdapi.APIV1POSTWalletRenewRequest{
		WalletHandleToken: handleToken,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTWalletRenewResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal("test-wallet", resp.WalletHandle.Wallet.Name)
	a.Greater(resp.WalletHandle.ExpiresSeconds, int64(0))
}

func TestWalletReleaseHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)

	// Release the handle
	req := authedRequest("POST", "/v1/wallet/release", kmdapi.APIV1POSTWalletReleaseRequest{
		WalletHandleToken: handleToken,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)
	a.Equal(http.StatusOK, rr.Code)

	// Now using the released handle should fail
	req = authedRequest("POST", "/v1/wallet/info", kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: handleToken,
	})
	rr = httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)
	a.Equal(http.StatusUnauthorized, rr.Code)
}

func TestInvalidHandleToken(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)

	req := authedRequest("POST", "/v1/wallet/info", kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: "bogus-token",
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusUnauthorized, rr.Code)
	var resp kmdapi.APIV1ResponseEnvelope
	decodeResponse(t, rr, &resp)
	a.True(resp.Error)
}

// --- Key operation tests ---

func TestGenerateKeyHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.generatedAddr = crypto.Digest{1, 2, 3}
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/key", kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: handleToken,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTKeyResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	expected := basics.Address(th.wallet.generatedAddr).GetUserAddress()
	a.Equal(expected, resp.Address)
}

func TestListKeysHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	addr1 := crypto.Digest{1}
	addr2 := crypto.Digest{2}
	th.wallet.keys = []crypto.Digest{addr1, addr2}
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/key/list", kmdapi.APIV1POSTKeyListRequest{
		WalletHandleToken: handleToken,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTKeyListResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Len(resp.Addresses, 2)
	a.Equal(basics.Address(addr1).GetUserAddress(), resp.Addresses[0])
	a.Equal(basics.Address(addr2).GetUserAddress(), resp.Addresses[1])
}

func TestImportKeyHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.importedAddr = crypto.Digest{42}
	handleToken := th.initSession(t)

	var sk crypto.PrivateKey
	sk[0] = 1

	req := authedRequest("POST", "/v1/key/import", kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: handleToken,
		PrivateKey:        sk,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTKeyImportResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal(basics.Address(crypto.Digest{42}).GetUserAddress(), resp.Address)
	a.Equal(sk, th.wallet.gotSK)
}

func TestExportKeyHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.exportedKey[0] = 0xAB
	handleToken := th.initSession(t)

	addr := basics.Address(crypto.Digest{1}).GetUserAddress()
	req := authedRequest("POST", "/v1/key/export", kmdapi.APIV1POSTKeyExportRequest{
		WalletHandleToken: handleToken,
		Address:           addr,
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTKeyExportResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal(byte(0xAB), resp.PrivateKey[0])
	a.Equal(crypto.Digest{1}, th.wallet.gotAddr)
	a.Equal([]byte(testPassword), th.wallet.gotPassword)
}

func TestDeleteKeyHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)

	addr := basics.Address(crypto.Digest{1}).GetUserAddress()
	req := authedRequest("DELETE", "/v1/key", kmdapi.APIV1DELETEKeyRequest{
		WalletHandleToken: handleToken,
		Address:           addr,
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1DELETEKeyResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal(crypto.Digest{1}, th.wallet.gotAddr)
	a.Equal([]byte(testPassword), th.wallet.gotPassword)
}

func TestExportMasterKeyHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.masterKey = crypto.MasterDerivationKey{1, 2, 3}
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/master-key/export", kmdapi.APIV1POSTMasterKeyExportRequest{
		WalletHandleToken: handleToken,
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTMasterKeyExportResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal(crypto.MasterDerivationKey{1, 2, 3}, resp.MasterDerivationKey)
	a.Equal([]byte(testPassword), th.wallet.gotPassword)
}

// --- Transaction signing tests ---

func TestSignTransactionHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.signedTx = []byte("signed-tx-bytes")
	handleToken := th.initSession(t)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender: basics.Address{7},
		},
	}
	var pk crypto.PublicKey
	pk[0] = 8

	req := authedRequest("POST", "/v1/transaction/sign", kmdapi.APIV1POSTTransactionSignRequest{
		WalletHandleToken: handleToken,
		Transaction:       protocol.Encode(&tx),
		PublicKey:         pk,
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTTransactionSignResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal([]byte("signed-tx-bytes"), resp.SignedTransaction)
	a.Equal(tx, th.wallet.gotTx)
	a.Equal(pk, th.wallet.gotPK)
	a.Equal([]byte(testPassword), th.wallet.gotPassword)
}

func TestSignProgramHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.signedProgram = []byte("signed-program")
	handleToken := th.initSession(t)

	addr := basics.Address(crypto.Digest{5}).GetUserAddress()
	req := authedRequest("POST", "/v1/program/sign", kmdapi.APIV1POSTProgramSignRequest{
		WalletHandleToken: handleToken,
		Address:           addr,
		Program:           []byte{0x01},
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTProgramSignResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal([]byte("signed-program"), resp.Signature)
	a.Equal([]byte{0x01}, th.wallet.gotProgram)
	a.Equal(crypto.Digest{5}, th.wallet.gotAddr)
	a.Equal([]byte(testPassword), th.wallet.gotPassword)
}

// --- Multisig tests ---

func TestMultisigListHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.multisigAddrs = []crypto.Digest{{10}, {20}}
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/multisig/list", kmdapi.APIV1POSTMultisigListRequest{
		WalletHandleToken: handleToken,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTMultisigListResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Len(resp.Addresses, 2)
}

func TestMultisigImportHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.multisigAddr = crypto.Digest{99}
	handleToken := th.initSession(t)

	var pk1, pk2 crypto.PublicKey
	pk1[0] = 1
	pk2[0] = 2

	req := authedRequest("POST", "/v1/multisig/import", kmdapi.APIV1POSTMultisigImportRequest{
		WalletHandleToken: handleToken,
		Version:           1,
		Threshold:         2,
		PKs:               []crypto.PublicKey{pk1, pk2},
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTMultisigImportResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal(basics.Address(crypto.Digest{99}).GetUserAddress(), resp.Address)
	a.Equal(uint8(1), th.wallet.gotVersion)
	a.Equal(uint8(2), th.wallet.gotThreshold)
	a.Equal([]crypto.PublicKey{pk1, pk2}, th.wallet.gotPKs)
}

func TestMultisigExportHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	var pk1 crypto.PublicKey
	pk1[0] = 1
	th.wallet.multisigVersion = 1
	th.wallet.multisigThresh = 2
	th.wallet.multisigPKs = []crypto.PublicKey{pk1}
	handleToken := th.initSession(t)

	addr := basics.Address(crypto.Digest{1}).GetUserAddress()
	req := authedRequest("POST", "/v1/multisig/export", kmdapi.APIV1POSTMultisigExportRequest{
		WalletHandleToken: handleToken,
		Address:           addr,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTMultisigExportResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal(uint8(1), resp.Version)
	a.Equal(uint8(2), resp.Threshold)
	a.Len(resp.PKs, 1)
}

func TestDeleteMultisigHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)

	addr := basics.Address(crypto.Digest{1}).GetUserAddress()
	req := authedRequest("DELETE", "/v1/multisig", kmdapi.APIV1DELETEMultisigRequest{
		WalletHandleToken: handleToken,
		Address:           addr,
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1DELETEMultisigResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.Equal(crypto.Digest{1}, th.wallet.gotAddr)
	a.Equal([]byte(testPassword), th.wallet.gotPassword)
}

func TestMultisigSignTransactionHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.multisigSig = crypto.MultisigSig{
		Version:   1,
		Threshold: 2,
	}
	handleToken := th.initSession(t)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender: basics.Address{7},
		},
	}
	var pk crypto.PublicKey
	pk[0] = 8
	partial := crypto.MultisigSig{Version: 1, Threshold: 2, Subsigs: []crypto.MultisigSubsig{{Key: pk}}}
	signer := crypto.Digest{9}

	req := authedRequest("POST", "/v1/multisig/sign", kmdapi.APIV1POSTMultisigTransactionSignRequest{
		WalletHandleToken: handleToken,
		Transaction:       protocol.Encode(&tx),
		PublicKey:         pk,
		PartialMsig:       partial,
		WalletPassword:    testPassword,
		AuthAddr:          signer,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTMultisigTransactionSignResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.NotEmpty(resp.Multisig)
	a.Equal(tx, th.wallet.gotTx)
	a.Equal(pk, th.wallet.gotPK)
	a.Equal(partial, th.wallet.gotPartial)
	a.Equal([]byte(testPassword), th.wallet.gotPassword)
	a.Equal(signer, th.wallet.gotAddr)
}

func TestMultisigSignProgramHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	th.wallet.multisigSig = crypto.MultisigSig{
		Version:   1,
		Threshold: 2,
	}
	handleToken := th.initSession(t)

	var pk crypto.PublicKey
	pk[0] = 8
	partial := crypto.MultisigSig{Version: 1, Threshold: 2, Subsigs: []crypto.MultisigSubsig{{Key: pk}}}

	addr := basics.Address(crypto.Digest{1}).GetUserAddress()
	req := authedRequest("POST", "/v1/multisig/signprogram", kmdapi.APIV1POSTMultisigProgramSignRequest{
		WalletHandleToken: handleToken,
		Address:           addr,
		Program:           []byte{0x01},
		PublicKey:         pk,
		PartialMsig:       partial,
		WalletPassword:    testPassword,
		UseLegacyMsig:     true,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	var resp kmdapi.APIV1POSTMultisigProgramSignResponse
	decodeResponse(t, rr, &resp)
	a.False(resp.Error)
	a.NotEmpty(resp.Multisig)
	a.Equal([]byte{0x01}, th.wallet.gotProgram)
	a.Equal(crypto.Digest{1}, th.wallet.gotAddr)
	a.Equal(pk, th.wallet.gotPK)
	a.Equal(partial, th.wallet.gotPartial)
	a.Equal([]byte(testPassword), th.wallet.gotPassword)
	a.True(th.wallet.gotLegacy)
}

// --- Error handling tests ---

func TestWalletErrorResponse(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)
	th.wallet.err = errors.New("wallet failure")

	addr := basics.Address(crypto.Digest{5}).GetUserAddress()
	req := authedRequest("POST", "/v1/program/sign", kmdapi.APIV1POSTProgramSignRequest{
		WalletHandleToken: handleToken,
		Address:           addr,
		Program:           []byte{0x01},
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusBadRequest, rr.Code)
	var resp kmdapi.APIV1ResponseEnvelope
	decodeResponse(t, rr, &resp)
	a.True(resp.Error)
	a.Equal("wallet failure", resp.Message)
}

func TestMalformedJSONBody(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)

	req := httptest.NewRequest("POST", "/v1/wallet/info", strings.NewReader("{invalid json"))
	req.Header.Set("X-KMD-API-Token", testToken)
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusBadRequest, rr.Code)
	var resp kmdapi.APIV1ResponseEnvelope
	decodeResponse(t, rr, &resp)
	a.True(resp.Error)
	a.Contains(resp.Message, "could not decode")
}

func TestInvalidAddressFormat(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/key/export", kmdapi.APIV1POSTKeyExportRequest{
		WalletHandleToken: handleToken,
		Address:           "not-a-valid-address",
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusBadRequest, rr.Code)
	var resp kmdapi.APIV1ResponseEnvelope
	decodeResponse(t, rr, &resp)
	a.True(resp.Error)
	a.Contains(resp.Message, "could not decode address")
}

func TestInvalidTransactionEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/transaction/sign", kmdapi.APIV1POSTTransactionSignRequest{
		WalletHandleToken: handleToken,
		Transaction:       []byte("not a valid msgpack transaction"),
		WalletPassword:    testPassword,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusBadRequest, rr.Code)
	var resp kmdapi.APIV1ResponseEnvelope
	decodeResponse(t, rr, &resp)
	a.True(resp.Error)
	a.Contains(resp.Message, "could not decode transaction")
}

// allV1Endpoints lists every v1 route. GET /v1/wallets, POST /v1/wallet,
// /v1/wallet/init and /v1/wallet/rename call package-level wallet driver
// functions, so only the auth tests below exercise them.
var allV1Endpoints = []struct {
	method string
	path   string
}{
	{"GET", "/v1/wallets"},
	{"POST", "/v1/wallet"},
	{"POST", "/v1/wallet/init"},
	{"POST", "/v1/wallet/release"},
	{"POST", "/v1/wallet/renew"},
	{"POST", "/v1/wallet/rename"},
	{"POST", "/v1/wallet/info"},
	{"POST", "/v1/master-key/export"},
	{"POST", "/v1/key/list"},
	{"POST", "/v1/key/import"},
	{"POST", "/v1/key/export"},
	{"POST", "/v1/key"},
	{"DELETE", "/v1/key"},
	{"POST", "/v1/multisig/list"},
	{"POST", "/v1/multisig/sign"},
	{"POST", "/v1/multisig/signprogram"},
	{"POST", "/v1/multisig/import"},
	{"POST", "/v1/multisig/export"},
	{"DELETE", "/v1/multisig"},
	{"POST", "/v1/transaction/sign"},
	{"POST", "/v1/program/sign"},
}

func TestAuthRejectsNoToken(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)

	for _, ep := range allV1Endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		rr := httptest.NewRecorder()
		th.handler.ServeHTTP(rr, req)
		a.Equal(http.StatusUnauthorized, rr.Code, "%s %s without token should be 401", ep.method, ep.path)
	}
}

func TestAuthRejectsWrongToken(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)

	for _, ep := range allV1Endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		req.Header.Set("X-KMD-API-Token", strings.Repeat("b", 64))
		rr := httptest.NewRecorder()
		th.handler.ServeHTTP(rr, req)
		a.Equal(http.StatusUnauthorized, rr.Code, "%s %s with wrong token should be 401", ep.method, ep.path)
	}
}

func TestAuthAcceptsValidToken(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)

	// With a valid token, every endpoint should get past auth and fail to
	// decode the malformed body. GET /v1/wallets reads no body and would
	// query the real wallet drivers, so it is skipped.
	for _, ep := range allV1Endpoints {
		if ep.method == "GET" {
			continue
		}
		req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{bad json"))
		req.Header.Set("X-KMD-API-Token", testToken)
		rr := httptest.NewRecorder()
		th.handler.ServeHTTP(rr, req)
		a.Equal(http.StatusBadRequest, rr.Code,
			"%s %s with valid token should be 400 (got %d)", ep.method, ep.path, rr.Code)
	}
}

func TestEmptyRequestBody(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)

	// POST with empty body should return 400 (decode error) not panic
	req := httptest.NewRequest("POST", "/v1/wallet/info", nil)
	req.Header.Set("X-KMD-API-Token", testToken)
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusBadRequest, rr.Code)
}

func TestResponseContentType(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)
	handleToken := th.initSession(t)

	req := authedRequest("POST", "/v1/wallet/info", kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: handleToken,
	})
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	a.Equal("application/json", rr.Header().Get("Content-Type"))
}

func TestErrorResponseContentType(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	th := newTestHarness(t)

	// Auth error should also return JSON
	req := httptest.NewRequest("GET", "/v1/wallets", nil)
	rr := httptest.NewRecorder()
	th.handler.ServeHTTP(rr, req)

	a.Equal(http.StatusUnauthorized, rr.Code)
	a.Equal("application/json", rr.Header().Get("Content-Type"))
}
