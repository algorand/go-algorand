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

package kmdapi

import (
	"errors"
)

// APIV1Response is the interface that all API V1 responses must satisfy
type APIV1Response interface {
	GetError() error
}

// APIV1ResponseEnvelope is a common envelope that all API V1 responses must embed
type APIV1ResponseEnvelope struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Error   bool     `json:"error"`
	Message string   `json:"message"`
}

// GetError allows VersionResponse to satisfy the APIV1Response interface, even
// though it can never return an error and is not versioned
func (r VersionsResponse) GetError() error {
	return nil
}

// GetError allows responses that embed an APIV1ResponseEnvelope to satisfy the
// APIV1Response interface
func (r APIV1ResponseEnvelope) GetError() error {
	if r.Error {
		return errors.New(r.Message)
	}
	return nil
}

// VersionsResponse is the response to `GET /versions`
// friendly:VersionsResponse
type VersionsResponse struct {
	_struct  struct{} `codec:",omitempty,omitemptyarray"`
	Versions []string `json:"versions"`
}

// swagger:response VersionsResponse
type versionsResponse struct {
	//in:body
	Body *VersionsResponse
}

// APIV1GETWalletsResponse is the response to `GET /v1/wallets`
// friendly:ListWalletsResponse
type APIV1GETWalletsResponse struct {
	APIV1ResponseEnvelope
	Wallets []APIV1Wallet `json:"wallets"`
}

// swagger:response ListWalletsResponse
type listWalletsResponse struct {
	//in: body
	Body *APIV1GETWalletsResponse
}

// APIV1POSTWalletResponse is the response to `POST /v1/wallet`
// friendly:CreateWalletResponse
type APIV1POSTWalletResponse struct {
	APIV1ResponseEnvelope
	Wallet APIV1Wallet `json:"wallet"`
}

// swagger:response CreateWalletResponse
type createWalletResponse struct {
	//	in:body
	Body *APIV1POSTWalletResponse
}

// APIV1POSTWalletInitResponse is the response to `POST /v1/wallet/init`
// friendly:InitWalletHandleTokenResponse
type APIV1POSTWalletInitResponse struct {
	APIV1ResponseEnvelope
	WalletHandleToken string `json:"wallet_handle_token"`
}

// swagger:response InitWalletHandleTokenResponse
type initWalletHandleTokenResponse struct {
	//	in:body
	Body *APIV1POSTWalletInitResponse
}

// APIV1POSTWalletReleaseResponse is the response to `POST /v1/wallet/release`
// friendly:ReleaseWalletHandleTokenResponse
type APIV1POSTWalletReleaseResponse struct {
	APIV1ResponseEnvelope
}

// swagger:response ReleaseWalletHandleTokenResponse
type releaseWalletHandleTokenResponse struct {
	//	in:body
	Body *APIV1POSTWalletReleaseResponse
}

// APIV1POSTWalletRenewResponse is the response to `POST /v1/wallet/renew`
// friendly:RenewWalletHandleTokenResponse
type APIV1POSTWalletRenewResponse struct {
	APIV1ResponseEnvelope
	WalletHandle APIV1WalletHandle `json:"wallet_handle"`
}

// swagger:response RenewWalletHandleTokenResponse
type renewWalletHandleTokenResponse struct {
	//	in:body
	Body *APIV1POSTWalletRenewResponse
}

// APIV1POSTWalletRenameResponse is the response to `POST /v1/wallet/rename`
// friendly:RenameWalletResponse
type APIV1POSTWalletRenameResponse struct {
	APIV1ResponseEnvelope
	Wallet APIV1Wallet `json:"wallet"`
}

// swagger:response RenameWalletResponse
type renameWalletResponse struct {
	//	in:body
	Body *APIV1POSTWalletRenameResponse
}

// APIV1POSTWalletInfoResponse is the response to `POST /v1/wallet/info`
// friendly:WalletInfoResponse
type APIV1POSTWalletInfoResponse struct {
	APIV1ResponseEnvelope
	WalletHandle APIV1WalletHandle `json:"wallet_handle"`
}

// swagger:response WalletInfoResponse
type walletInfoResponse struct {
	//	in:body
	Body *APIV1POSTWalletInfoResponse
}

// APIV1POSTMasterKeyExportResponse is the reponse to `POST /v1/master-key/export`
// friendly:ExportMasterKeyResponse
type APIV1POSTMasterKeyExportResponse struct {
	APIV1ResponseEnvelope
	MasterDerivationKey APIV1MasterDerivationKey `json:"master_derivation_key"`
}

// swagger:response ExportMasterKeyResponse
type exportMasterKeyResponse struct {
	//	in:body
	Body *APIV1POSTMasterKeyExportResponse
}

// APIV1POSTKeyImportResponse is the repsonse to `POST /v1/key/import`
// friendly:ImportKeyResponse
type APIV1POSTKeyImportResponse struct {
	APIV1ResponseEnvelope
	Address string `json:"address"`
}

// swagger:response ImportKeyResponse
type importKeyResponse struct {
	//	in:body
	Body *APIV1POSTKeyImportResponse
}

// APIV1POSTKeyExportResponse is the reponse to `POST /v1/key/export`
// friendly:ExportKeyResponse
type APIV1POSTKeyExportResponse struct {
	APIV1ResponseEnvelope
	PrivateKey APIV1PrivateKey `json:"private_key"`
}

// swagger:response ExportKeyResponse
type exportKeyResponse struct {
	//	in:body
	Body *APIV1POSTKeyExportResponse
}

// APIV1POSTKeyResponse is the response to `POST /v1/key`
// friendly:GenerateKeyResponse
type APIV1POSTKeyResponse struct {
	APIV1ResponseEnvelope
	Address string `json:"address"`
}

// swagger:response GenerateKeyResponse
type generateKeyResponse struct {
	//	in:body
	Body *APIV1POSTKeyResponse
}

// APIV1DELETEKeyResponse is the response to `DELETE /v1/key`
// friendly:DeleteKeyResponse
type APIV1DELETEKeyResponse struct {
	APIV1ResponseEnvelope
}

// swagger:response DeleteKeyResponse
type deleteKeyResponse struct {
	//	in:body
	Body *APIV1DELETEKeyResponse
}

// APIV1POSTKeyListResponse is the response to `POST /v1/key/list`
// friendly:ListKeysResponse
type APIV1POSTKeyListResponse struct {
	APIV1ResponseEnvelope
	Addresses []string `json:"addresses"`
}

// swagger:response ListKeysResponse
type listKeysResponse struct {
	//in: body
	Body *APIV1POSTKeyListResponse
}

// APIV1POSTTransactionSignResponse is the repsonse to `POST /v1/transaction/sign`
// friendly:SignTransactionResponse
type APIV1POSTTransactionSignResponse struct {
	APIV1ResponseEnvelope

	// swagger:strfmt byte
	SignedTransaction []byte `json:"signed_transaction"`
}

// swagger:response SignTransactionResponse
type signTransactionResponse struct {
	//	in:body
	Body *APIV1POSTTransactionSignResponse
}

// APIV1POSTProgramSignResponse is the repsonse to `POST /v1/data/sign`
// friendly:SignProgramResponse
type APIV1POSTProgramSignResponse struct {
	APIV1ResponseEnvelope

	// swagger:strfmt byte
	Signature []byte `json:"sig"`
}

// swagger:response SignProgramResponse
type signProgramResponse struct {
	//	in:body
	Body *APIV1POSTProgramSignResponse
}

// APIV1POSTMultisigListResponse is the response to `POST /v1/multisig/list`
// friendly:ListMultisigResponse
type APIV1POSTMultisigListResponse struct {
	APIV1ResponseEnvelope
	Addresses []string `json:"addresses"`
}

// swagger:response ListMultisigResponse
type listMultisigResponse struct {
	//	in:body
	Body *APIV1POSTMultisigListResponse
}

// APIV1POSTMultisigImportResponse is the response to `POST /v1/multisig/import`
// friendly:ImportMultisigResponse
type APIV1POSTMultisigImportResponse struct {
	APIV1ResponseEnvelope
	Address string `json:"address"`
}

// swagger:response ImportMultisigResponse
type importMultisigResponse struct {
	//	in:body
	Body *APIV1POSTMultisigImportResponse
}

// APIV1POSTMultisigExportResponse is the response to `POST /v1/multisig/export`
// friendly:ExportMultisigResponse
type APIV1POSTMultisigExportResponse struct {
	APIV1ResponseEnvelope
	Version   uint8            `json:"multisig_version"`
	Threshold uint8            `json:"threshold"`
	PKs       []APIV1PublicKey `json:"pks"`
}

// swagger:response ExportMultisigResponse
type exportMultisigResponse struct {
	//	in:body
	Body *APIV1POSTMultisigExportResponse
}

// APIV1DELETEMultisigResponse is the response to POST /v1/multisig/delete`
// friendly:DeleteMultisigResponse
type APIV1DELETEMultisigResponse struct {
	APIV1ResponseEnvelope
}

// swagger:response DeleteMultisigResponse
type deleteMultisigResponse struct {
	//in:body
	Body *APIV1DELETEMultisigResponse
}

// APIV1POSTMultisigTransactionSignResponse is the response to `POST /v1/multisig/sign`
// friendly:SignMultisigResponse
type APIV1POSTMultisigTransactionSignResponse struct {
	APIV1ResponseEnvelope

	// swagger:strfmt byte
	Multisig []byte `json:"multisig"`
}

// swagger:response SignMultisigResponse
type signMultisigResponse struct {
	//	in:body
	Body *APIV1POSTMultisigTransactionSignResponse
}

// APIV1POSTMultisigProgramSignResponse is the response to `POST /v1/multisig/signdata`
// friendly:SignProgramMultisigResponse
type APIV1POSTMultisigProgramSignResponse struct {
	APIV1ResponseEnvelope

	// swagger:strfmt byte
	Multisig []byte `json:"multisig"`
}

// swagger:response SignProgramMultisigResponse
type signProgramMultisigResponse struct {
	//	in:body
	Body *APIV1POSTMultisigProgramSignResponse
}
