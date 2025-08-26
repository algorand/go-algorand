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

package kmdapi

import (
	"github.com/algorand/go-algorand/crypto"
)

// APIV1Request is the interface that all API V1 requests must satisfy
//
// swagger:ignore
type APIV1Request interface{} // we need to tell swagger to ignore due to bug (go-swagger/issues/1436)

// VersionsRequest is the request for `GET /versions`
//
// swagger:model VersionsRequest
type VersionsRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
}

// APIV1GETWalletsRequest is the request for `GET /v1/wallets`
//
// swagger:model ListWalletsRequest
type APIV1GETWalletsRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
}

// APIV1POSTWalletRequest is the request for `POST /v1/wallet`
//
// swagger:model CreateWalletRequest
type APIV1POSTWalletRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletName          string                   `json:"wallet_name"`
	WalletDriverName    string                   `json:"wallet_driver_name"`
	WalletPassword      string                   `json:"wallet_password"`
	MasterDerivationKey APIV1MasterDerivationKey `json:"master_derivation_key"`
}

// APIV1POSTWalletInitRequest is the request for `POST /v1/wallet/init`
//
// swagger:model InitWalletHandleTokenRequest
type APIV1POSTWalletInitRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletID       string `json:"wallet_id"`
	WalletPassword string `json:"wallet_password"`
}

// APIV1POSTWalletReleaseRequest is the request for `POST /v1/wallet/release`
//
// swagger:model ReleaseWalletHandleTokenRequest
type APIV1POSTWalletReleaseRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
}

// APIV1POSTWalletRenewRequest is the request for `POST /v1/wallet/renew`
//
// swagger:model RenewWalletHandleTokenRequest
type APIV1POSTWalletRenewRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
}

// APIV1POSTWalletRenameRequest is the request for `POST /v1/wallet/rename`
//
// swagger:model RenameWalletRequest
type APIV1POSTWalletRenameRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletID       string `json:"wallet_id"`
	WalletPassword string `json:"wallet_password"`
	NewWalletName  string `json:"wallet_name"`
}

// APIV1POSTWalletInfoRequest is the request for `POST /v1/wallet/info`
//
// swagger:model WalletInfoRequest
type APIV1POSTWalletInfoRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
}

// APIV1POSTMasterKeyExportRequest is the request for `POST /v1/master-key/export`
//
// swagger:model ExportMasterKeyRequest
type APIV1POSTMasterKeyExportRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	WalletPassword    string `json:"wallet_password"`
}

// APIV1POSTKeyImportRequest is the request for `POST /v1/key/import`
//
// swagger:model ImportKeyRequest
type APIV1POSTKeyImportRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string            `json:"wallet_handle_token"`
	PrivateKey        crypto.PrivateKey `json:"private_key"`
}

// APIV1POSTKeyExportRequest is the request for `POST /v1/key/export`
//
// swagger:model ExportKeyRequest
type APIV1POSTKeyExportRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	Address           string `json:"address"`
	WalletPassword    string `json:"wallet_password"`
}

// APIV1POSTKeyRequest is the request for `POST /v1/key`
//
// swagger:model GenerateKeyRequest
type APIV1POSTKeyRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	DisplayMnemonic   bool   `json:"display_mnemonic"`
}

// APIV1DELETEKeyRequest is the request for `DELETE /v1/key`
//
// swagger:model DeleteKeyRequest
type APIV1DELETEKeyRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	Address           string `json:"address"`
	WalletPassword    string `json:"wallet_password"`
}

// APIV1POSTKeyListRequest is the request for `POST /v1/key/list`
//
// swagger:model ListKeysRequest
type APIV1POSTKeyListRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
}

// APIV1POSTTransactionSignRequest is the request for `POST /v1/transaction/sign`
//
// swagger:model SignTransactionRequest
type APIV1POSTTransactionSignRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	// Base64 encoding of msgpack encoding of a `Transaction` object
	// Note: SDK and goal usually generate `SignedTxn` objects
	//   in that case, the field `txn` / `Transaction` of the
	//   generated `SignedTxn` object needs to be used
	//
	// swagger:strfmt byte
	Transaction    []byte           `json:"transaction"`
	PublicKey      crypto.PublicKey `json:"public_key"`
	WalletPassword string           `json:"wallet_password"`
}

// APIV1POSTProgramSignRequest is the request for `POST /v1/program/sign`
//
// swagger:model SignProgramRequest
type APIV1POSTProgramSignRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	Address           string `json:"address"`
	// swagger:strfmt byte
	Program        []byte `json:"data"`
	WalletPassword string `json:"wallet_password"`
}

// APIV1POSTMultisigListRequest is the request for `POST /v1/multisig/list`
//
// swagger:model ListMultisigRequest
type APIV1POSTMultisigListRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
}

// APIV1POSTMultisigImportRequest is the request for `POST /v1/multisig/import`
//
// swagger:model ImportMultisigRequest
type APIV1POSTMultisigImportRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string             `json:"wallet_handle_token"`
	Version           uint8              `json:"multisig_version"`
	Threshold         uint8              `json:"threshold"`
	PKs               []crypto.PublicKey `json:"pks"`
}

// APIV1POSTMultisigExportRequest is the request for `POST /v1/multisig/export`
//
// swagger:model ExportMultisigRequest
type APIV1POSTMultisigExportRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	Address           string `json:"address"`
}

// APIV1DELETEMultisigRequest is the request for `DELETE /v1/multisig`
//
// swagger:model DeleteMultisigRequest
type APIV1DELETEMultisigRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	Address           string `json:"address"`
	WalletPassword    string `json:"wallet_password"`
}

// APIV1POSTMultisigTransactionSignRequest is the request for `POST /v1/multisig/sign`
//
// swagger:model SignMultisigRequest
type APIV1POSTMultisigTransactionSignRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	// swagger:strfmt byte
	Transaction    []byte             `json:"transaction"`
	PublicKey      crypto.PublicKey   `json:"public_key"`
	PartialMsig    crypto.MultisigSig `json:"partial_multisig"`
	WalletPassword string             `json:"wallet_password"`
	AuthAddr       crypto.Digest      `json:"signer"`
}

// APIV1POSTMultisigProgramSignRequest is the request for `POST /v1/multisig/signprogram`
//
// swagger:model SignProgramMultisigRequest
type APIV1POSTMultisigProgramSignRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	WalletHandleToken string `json:"wallet_handle_token"`
	Address           string `json:"address"`
	// swagger:strfmt byte
	Program        []byte             `json:"data"`
	PublicKey      crypto.PublicKey   `json:"public_key"`
	PartialMsig    crypto.MultisigSig `json:"partial_multisig"`
	WalletPassword string             `json:"wallet_password"`
	UseLegacyMsig  bool               `json:"use_legacy_msig"`
}
