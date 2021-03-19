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
// swagger:response VersionsResponse
type VersionsResponse struct {
	//in: body
	Body struct{
		_struct  struct{} `codec:",omitempty,omitemptyarray"`
		Versions []string `json:"versions"`
	}

}

// APIV1GETWalletsResponse is the response to `GET /v1/wallets`
// friendly:ListWalletsResponse
// swagger:response ListWalletsResponse
type APIV1GETWalletsResponse struct {
	// in: body
	Body struct {
		APIV1ResponseEnvelope
		Wallets []APIV1Wallet `json:"wallets"`
	}
}

// APIV1POSTWalletResponse is the response to `POST /v1/wallet`
// friendly:CreateWalletResponse
// swagger:response CreateWalletResponse
type APIV1POSTWalletResponse struct {
	// in: body
	Body struct{
		APIV1ResponseEnvelope
		Wallet APIV1Wallet `json:"wallet"`
	}

}

// APIV1POSTWalletInitResponse is the response to `POST /v1/wallet/init`
// friendly:InitWalletHandleTokenResponse
// swagger:response InitWalletHandleTokenResponse
type APIV1POSTWalletInitResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		WalletHandleToken string `json:"wallet_handle_token"`
	}

}

// APIV1POSTWalletReleaseResponse is the response to `POST /v1/wallet/release`
// friendly:ReleaseWalletHandleTokenResponse
// swagger:response ReleaseWalletHandleTokenResponse
type APIV1POSTWalletReleaseResponse struct {
	//in: body
	Body APIV1ResponseEnvelope
}

// APIV1POSTWalletRenewResponse is the response to `POST /v1/wallet/renew`
// friendly:RenewWalletHandleTokenResponse
// swagger:response RenewWalletHandleTokenResponse
type APIV1POSTWalletRenewResponse struct {
	//in:body
	Body struct{
		APIV1ResponseEnvelope
		WalletHandle APIV1WalletHandle `json:"wallet_handle"`
	}

}

// APIV1POSTWalletRenameResponse is the response to `POST /v1/wallet/rename`
// friendly:RenameWalletResponse
// swagger:response RenameWalletResponse
type APIV1POSTWalletRenameResponse struct {
	//in:body
	Body struct{
		APIV1ResponseEnvelope
		Wallet APIV1Wallet `json:"wallet"`
	}

}

// APIV1POSTWalletInfoResponse is the response to `POST /v1/wallet/info`
// friendly:WalletInfoResponse
// swagger:response WalletInfoResponse
type APIV1POSTWalletInfoResponse struct {
	//in:body
	Body struct{
		APIV1ResponseEnvelope
		WalletHandle APIV1WalletHandle `json:"wallet_handle"`
	}

}

// APIV1POSTMasterKeyExportResponse is the reponse to `POST /v1/master-key/export`
// friendly:ExportMasterKeyResponse
// swagger:response ExportMasterKeyResponse
type APIV1POSTMasterKeyExportResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		MasterDerivationKey APIV1MasterDerivationKey `json:"master_derivation_key"`
	}

}

// APIV1POSTKeyImportResponse is the repsonse to `POST /v1/key/import`
// friendly:ImportKeyResponse
// swagger:response ImportKeyResponse
type APIV1POSTKeyImportResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		Address string `json:"address"`
	}

}

// APIV1POSTKeyExportResponse is the reponse to `POST /v1/key/export`
// friendly:ExportKeyResponse
// swagger:response ExportKeyResponse
type APIV1POSTKeyExportResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		PrivateKey APIV1PrivateKey `json:"private_key"`
	}
}

// APIV1POSTKeyResponse is the response to `POST /v1/key`
// friendly:GenerateKeyResponse
// swagger:response GenerateKeyResponse
type APIV1POSTKeyResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		Address string `json:"address"`
	}

}

// APIV1DELETEKeyResponse is the response to `DELETE /v1/key`
// friendly:DeleteKeyResponse
// swagger:response DeleteKeyResponse
type APIV1DELETEKeyResponse struct {
	//in: body
	Body APIV1ResponseEnvelope
}

// APIV1POSTKeyListResponse is the response to `POST /v1/key/list`
// friendly:ListKeysResponse
// swagger:response ListKeysResponse
type APIV1POSTKeyListResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		Addresses []string `json:"addresses"`
	}
}

// APIV1POSTTransactionSignResponse is the repsonse to `POST /v1/transaction/sign`
// friendly:SignTransactionResponse
// swagger:response SignTransactionResponse
type APIV1POSTTransactionSignResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		// swagger:strfmt byte
		SignedTransaction []byte `json:"signed_transaction"`
	}

}

// APIV1POSTProgramSignResponse is the repsonse to `POST /v1/data/sign`
// friendly:SignProgramResponse
// swagger:response SignProgramResponse
type APIV1POSTProgramSignResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		// swagger:strfmt byte
		Signature []byte `json:"sig"`
	}

}

// APIV1POSTMultisigListResponse is the response to `POST /v1/multisig/list`
// friendly:ListMultisigResponse
// swagger:response ListMultisigResponse
type APIV1POSTMultisigListResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		Addresses []string `json:"addresses"`
	}
}

// APIV1POSTMultisigImportResponse is the response to `POST /v1/multisig/import`
// friendly:ImportMultisigResponse
// swagger:response ImportMultisigResponse
type APIV1POSTMultisigImportResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		Address string `json:"address"`
	}

}

// APIV1POSTMultisigExportResponse is the response to `POST /v1/multisig/export`
// friendly:ExportMultisigResponse
// swagger:response ExportMultisigResponse
type APIV1POSTMultisigExportResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		Version   uint8            `json:"multisig_version"`
		Threshold uint8            `json:"threshold"`
		PKs       []APIV1PublicKey `json:"pks"`
	}

}

// APIV1DELETEMultisigResponse is the response to POST /v1/multisig/delete`
// friendly:DeleteMultisigResponse
// swagger:response DeleteMultisigResponse
type APIV1DELETEMultisigResponse struct {
	//in: body
	Body APIV1ResponseEnvelope
}

// APIV1POSTMultisigTransactionSignResponse is the response to `POST /v1/multisig/sign`
// friendly:SignMultisigResponse
// swagger:response SignMultisigResponse
type APIV1POSTMultisigTransactionSignResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		// swagger:strfmt byte
		Multisig []byte `json:"multisig"`
	}

}

// APIV1POSTMultisigProgramSignResponse is the response to `POST /v1/multisig/signdata`
// friendly:SignProgramMultisigResponse
// swagger:response SignProgramMultisigResponse
type APIV1POSTMultisigProgramSignResponse struct {
	//in: body
	Body struct{
		APIV1ResponseEnvelope
		// swagger:strfmt byte
		Multisig []byte `json:"multisig"`
	}
}
