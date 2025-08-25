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

package v1

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/daemon/kmd/session"
	"github.com/algorand/go-algorand/daemon/kmd/wallet"
	"github.com/algorand/go-algorand/daemon/kmd/wallet/driver"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// reqContext is passed to each of the handlers below via wrapCtx, allowing
// handlers to interact with kmd's session store
type reqContext struct {
	sm *session.Manager
}

// errorResponse sets the specified status code (should != 200), and fills in the
// the response envelope by setting Error to true and a Message to the passed
// user-readable error message.
func errorResponse(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := kmdapi.APIV1ResponseEnvelope{
		Error:   true,
		Message: err.Error(),
	}
	w.Write(protocol.EncodeJSON(resp))
}

// successResponse is a helper that returns a 200 and an encoded response
func successResponse(w http.ResponseWriter, resp kmdapi.APIV1Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(protocol.EncodeJSON(resp))
}

func encodeAddress(addr crypto.Digest) string {
	return basics.Address(addr).GetUserAddress()
}

// encodeAddresses turns raw addresses into checksummed strings suitable for
// displaying to users
func encodeAddresses(addrs []crypto.Digest) (userAddrs []string) {
	for _, addr := range addrs {
		userAddrs = append(userAddrs, encodeAddress(addr))
	}
	return
}

// apiWalletFromMetadata is a helper to convert our internal wallet metadata
// format into the APIV1 representation of a wallet
func apiWalletFromMetadata(metadata wallet.Metadata) kmdapi.APIV1Wallet {
	return kmdapi.APIV1Wallet{
		ID:                    string(metadata.ID),
		Name:                  string(metadata.Name),
		DriverName:            metadata.DriverName,
		DriverVersion:         metadata.DriverVersion,
		SupportsMnemonicUX:    metadata.SupportsMnemonicUX,
		SupportedTransactions: metadata.SupportedTransactions,
	}
}

// getWalletsHandler handles `GET /v1/wallets`
func getWalletsHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/wallets ListWallets
	//---
	//    Summary: List wallets
	//    Description: Lists all of the wallets that kmd is aware of.
	//    Produces:
	//    - application/json
	//    Parameters:
	//    - name: List Wallet Request
	//      in: body
	//      required: false
	//      schema:
	//        "$ref": "#/definitions/ListWalletsRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ListWalletsResponse"

	// List all wallets from all wallet drivers
	walletMetadatas, err := driver.ListWalletMetadatas()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Fill in the APIV1 representation of each wallet
	var apiWallets []kmdapi.APIV1Wallet
	for _, metadata := range walletMetadatas {
		apiWallets = append(apiWallets, apiWalletFromMetadata(metadata))
	}

	// Wrap the wallets in an API response
	resp := kmdapi.APIV1GETWalletsResponse{
		Wallets: apiWallets,
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postWalletHandler handles `POST /v1/wallet`
func postWalletHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/wallet CreateWallet
	//---
	//    Summary: Create a wallet
	//    Description: Create a new wallet (collection of keys) with the given parameters.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Create Wallet Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/CreateWalletRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/CreateWalletResponse"
	var req kmdapi.APIV1POSTWalletRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet driver
	walletDriver, err := driver.FetchWalletDriver(req.WalletDriverName)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Generate a wallet ID
	walletID, err := wallet.GenerateWalletID()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// If the wallet name is blank, use the wallet ID
	walletName := []byte(req.WalletName)
	if len(walletName) == 0 {
		walletName = walletID
	}

	// Create the wallet via its driver
	err = walletDriver.CreateWallet(walletName, walletID, []byte(req.WalletPassword), req.MasterDerivationKey)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Fetch the wallet
	wallet, err := walletDriver.FetchWallet(walletID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Fetch metadata about the wallet we just created
	metadata, err := wallet.Metadata()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTWalletResponse{
		Wallet: apiWalletFromMetadata(metadata),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postWalletInitHandler handles `POST /v1/wallet/init`
func postWalletInitHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/wallet/init InitWalletHandleToken
	//---
	//    Summary: Initialize a wallet handle token
	//    Description: >
	//      Unlock the wallet and return a wallet handle token that can be used for subsequent operations.
	//      These tokens expire periodically and must be renewed. You can `POST` the token to `/v1/wallet/info`
	//      to see how much time remains until expiration, and renew it with `/v1/wallet/renew`. When you're done,
	//      you can invalidate the token with `/v1/wallet/release`.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Initialize Wallet Handle Token Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/InitWalletHandleTokenRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/InitWalletHandleTokenResponse"
	var req kmdapi.APIV1POSTWalletInitRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet
	wallet, err := driver.FetchWalletByID([]byte(req.WalletID))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Attempt to auth
	handleToken, err := ctx.sm.InitWalletHandle(wallet, []byte(req.WalletPassword))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTWalletInitResponse{
		WalletHandleToken: string(handleToken),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postWalletInfoHandler handles `POST /v1/wallet/info`
func postWalletInfoHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/wallet/info GetWalletInfo
	//---
	//    Summary: Get wallet info
	//    Description: >
	//      Returns information about the wallet associated with the passed wallet handle token.
	//      Additionally returns expiration information about the token itself.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Get Wallet Info Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/WalletInfoRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/WalletInfoResponse"
	var req kmdapi.APIV1POSTWalletInfoRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, expiresSeconds, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Fetch the wallet metadata
	metadata, err := wallet.Metadata()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTWalletInfoResponse{
		WalletHandle: kmdapi.APIV1WalletHandle{
			Wallet:         apiWalletFromMetadata(metadata),
			ExpiresSeconds: expiresSeconds,
		},
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postMasterKeyExportHandler handles `POST /v1/master-key/export`
func postMasterKeyExportHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/master-key/export ExportMasterKey
	//---
	//    Summary: Export the master derivation key from a wallet
	//    Description: >
	//      Export the master derivation key from the wallet. This key is a master "backup" key for
	//      the underlying wallet. With it, you can regenerate all of the wallets that have been
	//      generated with this wallet's `POST /v1/key` endpoint. This key will not allow you to recover
	//      keys imported from other wallets, however.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Export Master Key Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/ExportMasterKeyRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ExportMasterKeyResponse"
	var req kmdapi.APIV1POSTMasterKeyExportRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Export the master derivation key
	mdk, err := wallet.ExportMasterDerivationKey([]byte(req.WalletPassword))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTMasterKeyExportResponse{
		MasterDerivationKey: mdk,
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postWalletReleaseHandler handles `POST /v1/wallet/release`
func postWalletReleaseHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/wallet/release ReleaseWalletHandleToken
	//---
	//    Summary: Release a wallet handle token
	//    Description: Invalidate the passed wallet handle token, making it invalid for use in subsequent requests.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Release Wallet Handle Token Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/ReleaseWalletHandleTokenRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ReleaseWalletHandleTokenResponse"
	var req kmdapi.APIV1POSTWalletReleaseRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Release the WalletHandleToken
	err = ctx.sm.ReleaseWalletHandle([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTWalletReleaseResponse{}

	// Return and encode the response
	successResponse(w, resp)
}

// postWalletRenewHandler handles `POST /v1/wallet/renew`
func postWalletRenewHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/wallet/renew RenewWalletHandleToken
	//---
	//    Summary: Renew a wallet handle token
	//    Description: Renew a wallet handle token, increasing its expiration duration to its initial value
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Renew Wallet Handle Token Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/RenewWalletHandleTokenRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/RenewWalletHandleTokenResponse"
	var req kmdapi.APIV1POSTWalletRenewRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Renew the walletHandleToken + fetch the wallet
	wallet, expiresSeconds, err := ctx.sm.RenewWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Fetch the wallet metadata
	metadata, err := wallet.Metadata()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTWalletRenewResponse{
		WalletHandle: kmdapi.APIV1WalletHandle{
			Wallet:         apiWalletFromMetadata(metadata),
			ExpiresSeconds: expiresSeconds,
		},
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postWalletRenameHandler handles `POST /v1/wallet/rename`
func postWalletRenameHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/wallet/rename RenameWallet
	//---
	//    Summary: Rename a wallet
	//    Description: Rename the underlying wallet to something else
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Rename Wallet Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/RenameWalletRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/RenameWalletResponse"
	var req kmdapi.APIV1POSTWalletRenameRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet
	wallet, err := driver.FetchWalletByID([]byte(req.WalletID))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Fetch the wallet metadata
	metadata, err := wallet.Metadata()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Fetch the wallet driver
	driver, err := driver.FetchWalletDriver(metadata.DriverName)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Rename the wallet
	err = driver.RenameWallet([]byte(req.NewWalletName), metadata.ID, []byte(req.WalletPassword))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Fetch the renamed wallet metadata
	metadata, err = wallet.Metadata()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTWalletRenameResponse{
		Wallet: apiWalletFromMetadata(metadata),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postKeyImportHandler handles `POST /v1/key/import`
func postKeyImportHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/key/import ImportKey
	//---
	//    Summary: Import a key
	//    Description: >
	//      Import an externally generated key into the wallet. Note that if you wish to back up
	//      the imported key, you must do so by backing up the entire wallet database, because imported
	//      keys were not derived from the wallet's master derivation key.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Import Key Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/ImportKeyRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ImportKeyResponse"
	var req kmdapi.APIV1POSTKeyImportRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Import the key
	addr, err := wallet.ImportKey(req.PrivateKey)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTKeyImportResponse{
		Address: encodeAddress(addr),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postKeyExportHandler handles `POST /v1/key/export`
func postKeyExportHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/key/export ExportKey
	//---
	//    Summary: Export a key
	//    Description: Export the secret key associated with the passed public key.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Export Key Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/ExportKeyRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ExportKeyResponse"
	var req kmdapi.APIV1POSTKeyExportRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Decode the address
	reqAddr, err := basics.UnmarshalChecksumAddress(req.Address)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecodeAddress)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Export the key
	secretKey, err := wallet.ExportKey(crypto.Digest(reqAddr), []byte(req.WalletPassword))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTKeyExportResponse{
		PrivateKey: secretKey,
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postKeyHandler handles `POST /v1/key`
func postKeyHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/key GenerateKey
	//---
	//    Summary: Generate a key
	//    Produces:
	//    - application/json
	//    Description: >
	//      Generates the next key in the deterministic key sequence (as determined by the master derivation key)
	//      and adds it to the wallet, returning the public key.
	//    Parameters:
	//      - name: Generate Key Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/GenerateKeyRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/GenerateKeyResponse"
	var req kmdapi.APIV1POSTKeyRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Generate the key
	addr, err := wallet.GenerateKey(req.DisplayMnemonic)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTKeyResponse{
		Address: encodeAddress(addr),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// deleteKeyHandler handles `DELETE /v1/key`
func deleteKeyHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation DELETE /v1/key DeleteKey
	//---
	//    Summary: Delete a key
	//    Description: Deletes the key with the passed public key from the wallet.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Delete Key Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/DeleteKeyRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/DeleteKeyResponse"
	var req kmdapi.APIV1DELETEKeyRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Decode the address
	reqAddr, err := basics.UnmarshalChecksumAddress(req.Address)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecodeAddress)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Delete the key
	err = wallet.DeleteKey(crypto.Digest(reqAddr), []byte(req.WalletPassword))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1DELETEKeyResponse{}

	// Return and encode the response
	successResponse(w, resp)
}

// postKeyListHandler handles `POST /v1/key/list`
func postKeyListHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/key/list ListKeysInWallet
	//---
	//    Summary: List keys in wallet
	//    Description: Lists all of the public keys in this wallet. All of them have a stored private key.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: List Keys Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/ListKeysRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ListKeysResponse"
	var req kmdapi.APIV1POSTKeyListRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// List the addresses
	addrs, err := wallet.ListKeys()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTKeyListResponse{
		Addresses: encodeAddresses(addrs),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postTransactionSignHandler handles `POST /v1/transaction/sign`
func postTransactionSignHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/transaction/sign SignTransaction
	//---
	//    Summary: Sign a transaction
	//    Description: >
	//      Signs the passed transaction with a key from the wallet, determined
	//      by the sender encoded in the transaction.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Sign Transaction Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/SignTransactionRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/SignTransactionResponse"
	var req kmdapi.APIV1POSTTransactionSignRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Decode the transaction
	var tx transactions.Transaction
	err = protocol.Decode(req.Transaction, &tx)

	// Ensure we were able to decode the transaction
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecodeTx)
		return
	}

	// Sign the transaction
	stx, err := wallet.SignTransaction(tx, req.PublicKey, []byte(req.WalletPassword))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTTransactionSignResponse{
		SignedTransaction: stx,
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postProgramSignHandler handles `POST /v1/program/sign`
func postProgramSignHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/program/sign SignProgram
	//---
	//    Summary: Sign program
	//    Description: >
	//      Signs the passed program with a key from the wallet, determined
	//      by the account named in the request.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Sign Program Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/SignProgramRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/SignProgramResponse"
	var req kmdapi.APIV1POSTProgramSignRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Decode the address
	reqAddr, err := basics.UnmarshalChecksumAddress(req.Address)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecodeAddress)
		return
	}

	stx, err := wallet.SignProgram(req.Program, crypto.Digest(reqAddr), []byte(req.WalletPassword))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTProgramSignResponse{
		Signature: stx,
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postMultisigListHandler handles `POST /v1/multisig/list`
func postMultisigListHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/multisig/list ListMultisg
	//---
	//    Summary: List multisig accounts
	//    Description: Lists all of the multisig accounts whose preimages this wallet stores
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: List Multisig Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/ListMultisigRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ListMultisigResponse"
	var req kmdapi.APIV1POSTMultisigListRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// List the keys
	addrs, err := wallet.ListMultisigAddrs()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTMultisigListResponse{
		Addresses: encodeAddresses(addrs),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postMultisigImportHandler handles `POST /v1/multisig/import`
func postMultisigImportHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/multisig/import ImportMultisig
	//---
	//    Summary: Import a multisig account
	//    Description: >
	//      Generates a multisig account from the passed public keys array and multisig
	//      metadata, and stores all of this in the wallet.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Import Multisig Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/ImportMultisigRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ImportMultisigResponse"
	var req kmdapi.APIV1POSTMultisigImportRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Import the key
	addr, err := wallet.ImportMultisigAddr(req.Version, req.Threshold, req.PKs)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTMultisigImportResponse{
		Address: encodeAddress(addr),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postMultisigExportHandler handles `POST /v1/multisig/export`
func postMultisigExportHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/multisig/export ExportMultisig
	//---
	//    Summary: Export multisig address metadata
	//    Description: >
	//      Given a multisig address whose preimage this wallet stores, returns
	//      the information used to generate the address, including public keys,
	//      threshold, and multisig version.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Export Multisig Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/ExportMultisigRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/ExportMultisigResponse"
	var req kmdapi.APIV1POSTMultisigExportRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Decode the address
	reqAddr, err := basics.UnmarshalChecksumAddress(req.Address)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecodeAddress)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Export the key
	version, threshold, pks, err := wallet.LookupMultisigPreimage(crypto.Digest(reqAddr))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTMultisigExportResponse{
		Version:   version,
		Threshold: threshold,
		PKs:       pks,
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postMultisigTransactionSignHandler handles `POST /v1/multisig/sign`
func postMultisigTransactionSignHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/multisig/sign SignMultisigTransaction
	//---
	//    Summary: Sign a multisig transaction
	//    Description: >
	//      Start a multisig signature, or add a signature to a partially completed
	//      multisig signature object.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Sign Multisig Transaction Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/SignMultisigRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/SignMultisigResponse"
	var req kmdapi.APIV1POSTMultisigTransactionSignRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Decode the transaction
	var tx transactions.Transaction
	err = protocol.Decode(req.Transaction, &tx)

	// Ensure we were able to decode the transaction
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecodeTx)
		return
	}

	// Sign the transaction
	msig, err := wallet.MultisigSignTransaction(tx, req.PublicKey, req.PartialMsig, []byte(req.WalletPassword), req.AuthAddr)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTMultisigTransactionSignResponse{
		Multisig: protocol.Encode(&msig),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// postMultisigProgramSignHandler handles `POST /v1/multisig/signprogram`
func postMultisigProgramSignHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/multisig/signprogram SignMultisigProgram
	//---
	//    Summary: Sign a program for a multisig account
	//    Description: >
	//      Start a multisig signature, or add a signature to a partially completed
	//      multisig signature object.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Sign Multisig Program Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/SignProgramMultisigRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/SignProgramMultisigResponse"
	var req kmdapi.APIV1POSTMultisigProgramSignRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Decode the address
	reqAddr, err := basics.UnmarshalChecksumAddress(req.Address)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecodeAddress)
		return
	}

	// Sign the program
	msig, err := wallet.MultisigSignProgram(req.Program, crypto.Digest(reqAddr), req.PublicKey, req.PartialMsig, []byte(req.WalletPassword), req.UseLegacyMsig)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1POSTMultisigProgramSignResponse{
		Multisig: protocol.Encode(&msig),
	}

	// Return and encode the response
	successResponse(w, resp)
}

// deleteMultisigHandler handles `DELETE /v1/multisig`
func deleteMultisigHandler(ctx reqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation DELETE /v1/multisig DeleteMultisig
	//---
	//    Summary: Delete a multisig
	//    Description: >
	//      Deletes multisig preimage information for the passed address from the wallet.
	//    Produces:
	//    - application/json
	//    Parameters:
	//      - name: Delete Multisig Request
	//        in: body
	//        required: true
	//        schema:
	//          "$ref": "#/definitions/DeleteMultisigRequest"
	//    Responses:
	//      "200":
	//        "$ref": "#/responses/DeleteMultisigResponse"
	var req kmdapi.APIV1DELETEMultisigRequest

	// Decode the request
	decoder := protocol.NewJSONDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecode)
		return
	}

	// Decode the address
	reqAddr, err := basics.UnmarshalChecksumAddress(req.Address)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, errCouldNotDecodeAddress)
		return
	}

	// Fetch the wallet from the WalletHandleToken
	wallet, _, err := ctx.sm.AuthWithWalletHandleToken([]byte(req.WalletHandleToken))
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err)
		return
	}

	// Delete the key
	err = wallet.DeleteMultisigAddr(crypto.Digest(reqAddr), []byte(req.WalletPassword))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err)
		return
	}

	// Build the response
	resp := kmdapi.APIV1DELETEMultisigResponse{}

	// Return and encode the response
	successResponse(w, resp)
}

// wrapCtx is used to pass common context to each request without using any
// global variables.
func wrapCtx(ctx reqContext, handler func(reqContext, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		handler(ctx, w, r)
	}
}

// reqCallbackMiddlware calls the reqCB function once per request that passes
// through. We use this in server.go to kick a watchdog timer, so that we can
// kill kmd if we haven't received a request in a while.
func reqCallbackMiddleware(reqCB func()) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Call the callback
			reqCB()
			// Serve the request
			next.ServeHTTP(w, r)
		})
	}
}

// RegisterHandlers sets up the API handlers on the passed router
func RegisterHandlers(router *mux.Router, sm *session.Manager, log logging.Logger, apiToken string, reqCB func()) {
	// All /v1 requests require a valid auth token
	router.Use(authMiddleware(log, apiToken))

	// reqCB gets called each time a request matches a route
	router.Use(reqCallbackMiddleware(reqCB))

	// ctx holds the global context passed to each of the handlers
	ctx := reqContext{
		sm: sm,
	}

	router.HandleFunc("/wallets", wrapCtx(ctx, getWalletsHandler)).Methods("GET")
	router.HandleFunc("/wallet", wrapCtx(ctx, postWalletHandler)).Methods("POST")
	router.HandleFunc("/wallet/init", wrapCtx(ctx, postWalletInitHandler)).Methods("POST")
	router.HandleFunc("/wallet/release", wrapCtx(ctx, postWalletReleaseHandler)).Methods("POST")
	router.HandleFunc("/wallet/renew", wrapCtx(ctx, postWalletRenewHandler)).Methods("POST")
	router.HandleFunc("/wallet/rename", wrapCtx(ctx, postWalletRenameHandler)).Methods("POST")
	router.HandleFunc("/wallet/info", wrapCtx(ctx, postWalletInfoHandler)).Methods("POST")
	router.HandleFunc("/master-key/export", wrapCtx(ctx, postMasterKeyExportHandler)).Methods("POST")

	router.HandleFunc("/key/list", wrapCtx(ctx, postKeyListHandler)).Methods("POST")
	router.HandleFunc("/key/import", wrapCtx(ctx, postKeyImportHandler)).Methods("POST")
	router.HandleFunc("/key/export", wrapCtx(ctx, postKeyExportHandler)).Methods("POST")
	router.HandleFunc("/key", wrapCtx(ctx, postKeyHandler)).Methods("POST")
	router.HandleFunc("/key", wrapCtx(ctx, deleteKeyHandler)).Methods("DELETE")

	router.HandleFunc("/multisig/list", wrapCtx(ctx, postMultisigListHandler)).Methods("POST")
	router.HandleFunc("/multisig/sign", wrapCtx(ctx, postMultisigTransactionSignHandler)).Methods("POST")
	router.HandleFunc("/multisig/signprogram", wrapCtx(ctx, postMultisigProgramSignHandler)).Methods("POST")
	router.HandleFunc("/multisig/import", wrapCtx(ctx, postMultisigImportHandler)).Methods("POST")
	router.HandleFunc("/multisig/export", wrapCtx(ctx, postMultisigExportHandler)).Methods("POST")
	router.HandleFunc("/multisig", wrapCtx(ctx, deleteMultisigHandler)).Methods("DELETE")

	router.HandleFunc("/transaction/sign", wrapCtx(ctx, postTransactionSignHandler)).Methods("POST")
	router.HandleFunc("/program/sign", wrapCtx(ctx, postProgramSignHandler)).Methods("POST")
}
