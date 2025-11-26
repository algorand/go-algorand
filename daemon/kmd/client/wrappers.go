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

package client

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// Version wraps kmdapi.VersionsRequest
func (kcl KMDClient) Version() (resp kmdapi.VersionsResponse, err error) {
	req := kmdapi.VersionsRequest{}
	err = kcl.DoV1Request(req, &resp)
	return
}

// ListWallets wraps kmdapi.APIV1GETWalletsRequest
func (kcl KMDClient) ListWallets() (resp kmdapi.APIV1GETWalletsResponse, err error) {
	req := kmdapi.APIV1GETWalletsRequest{}
	err = kcl.DoV1Request(req, &resp)
	return
}

// GenerateKey wraps kmdapi.APIV1POSTKeyRequest
func (kcl KMDClient) GenerateKey(walletHandle []byte) (resp kmdapi.APIV1POSTKeyResponse, err error) {
	req := kmdapi.APIV1POSTKeyRequest{
		WalletHandleToken: string(walletHandle),
		DisplayMnemonic:   false,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// CreateWallet wraps kmdapi.APIV1POSTWalletRequest
func (kcl KMDClient) CreateWallet(walletName []byte, walletDriverName string, walletPassword []byte, walletMDK crypto.MasterDerivationKey) (resp kmdapi.APIV1POSTWalletResponse, err error) {
	req := kmdapi.APIV1POSTWalletRequest{
		WalletName:          string(walletName),
		WalletDriverName:    walletDriverName,
		WalletPassword:      string(walletPassword),
		MasterDerivationKey: walletMDK,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// RenameWallet wraps kmdapi.APIV1POSTWalletRenameRequest
func (kcl KMDClient) RenameWallet(walletID []byte, newWalletName []byte, walletPassword []byte) (resp kmdapi.APIV1POSTWalletRenameResponse, err error) {
	req := kmdapi.APIV1POSTWalletRenameRequest{
		WalletID:       string(walletID),
		NewWalletName:  string(newWalletName),
		WalletPassword: string(walletPassword),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// InitWallet wraps kmdapi.APIV1POSTWalletInitRequest
func (kcl KMDClient) InitWallet(walletID []byte, walletPassword []byte) (resp kmdapi.APIV1POSTWalletInitResponse, err error) {
	req := kmdapi.APIV1POSTWalletInitRequest{
		WalletID:       string(walletID),
		WalletPassword: string(walletPassword),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// ReleaseWalletHandle wraps kmdapi.APIV1POSTWalletReleaseRequest
func (kcl KMDClient) ReleaseWalletHandle(walletHandle []byte) (resp kmdapi.APIV1POSTWalletReleaseResponse, err error) {
	req := kmdapi.APIV1POSTWalletReleaseRequest{
		WalletHandleToken: string(walletHandle),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// ListKeys wraps kmdapi.APIV1POSTKeyListRequest
func (kcl KMDClient) ListKeys(walletHandle []byte) (resp kmdapi.APIV1POSTKeyListResponse, err error) {
	req := kmdapi.APIV1POSTKeyListRequest{
		WalletHandleToken: string(walletHandle),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// DeleteKey wraps kmdapi.APIV1DELETEKeyRequest
func (kcl KMDClient) DeleteKey(walletHandle []byte, pw []byte, addr string) (resp kmdapi.APIV1DELETEKeyResponse, err error) {
	req := kmdapi.APIV1DELETEKeyRequest{
		WalletHandleToken: string(walletHandle),
		Address:           addr,
		WalletPassword:    string(pw),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// ListMultisigAddrs wraps kmdapi.APIV1POSTMultisigListRequest
func (kcl KMDClient) ListMultisigAddrs(walletHandle []byte) (resp kmdapi.APIV1POSTMultisigListResponse, err error) {
	req := kmdapi.APIV1POSTMultisigListRequest{
		WalletHandleToken: string(walletHandle),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// ImportMultisigAddr wraps kmdapi.APIV1POSTMultisigImportRequest
func (kcl KMDClient) ImportMultisigAddr(walletHandle []byte, version, threshold uint8, pks []crypto.PublicKey) (resp kmdapi.APIV1POSTMultisigImportResponse, err error) {
	req := kmdapi.APIV1POSTMultisigImportRequest{
		WalletHandleToken: string(walletHandle),
		Version:           version,
		Threshold:         threshold,
		PKs:               pks,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// ExportMultisigAddr wraps kmdapi.APIV1POSTMultisigExportRequest
func (kcl KMDClient) ExportMultisigAddr(walletHandle []byte, addr string) (resp kmdapi.APIV1POSTMultisigExportResponse, err error) {
	req := kmdapi.APIV1POSTMultisigExportRequest{
		WalletHandleToken: string(walletHandle),
		Address:           addr,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// DeleteMultisigAddr wraps kmdapi.APIV1DELETEMultisigRequest
func (kcl KMDClient) DeleteMultisigAddr(walletHandle []byte, pw []byte, addr string) (resp kmdapi.APIV1DELETEMultisigResponse, err error) {
	req := kmdapi.APIV1DELETEMultisigRequest{
		WalletHandleToken: string(walletHandle),
		Address:           addr,
		WalletPassword:    string(pw),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// MultisigSignTransaction wraps kmdapi.APIV1POSTMultisigTransactionSignRequest
func (kcl KMDClient) MultisigSignTransaction(walletHandle, pw []byte, tx []byte, pk crypto.PublicKey, partial crypto.MultisigSig, msigSigner crypto.Digest) (resp kmdapi.APIV1POSTMultisigTransactionSignResponse, err error) {
	req := kmdapi.APIV1POSTMultisigTransactionSignRequest{
		WalletHandleToken: string(walletHandle),
		WalletPassword:    string(pw),
		Transaction:       tx,
		PublicKey:         pk,
		PartialMsig:       partial,
		AuthAddr:          msigSigner,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// MultisigSignProgram wraps kmdapi.APIV1POSTMultisigProgramSignRequest
func (kcl KMDClient) MultisigSignProgram(walletHandle, pw []byte, addr string, data []byte, pk crypto.PublicKey, partial crypto.MultisigSig, useLegacyMsig bool) (resp kmdapi.APIV1POSTMultisigProgramSignResponse, err error) {
	req := kmdapi.APIV1POSTMultisigProgramSignRequest{
		WalletHandleToken: string(walletHandle),
		WalletPassword:    string(pw),
		Program:           data,
		Address:           addr,
		PublicKey:         pk,
		PartialMsig:       partial,
		UseLegacyMsig:     useLegacyMsig,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// RenewWalletHandle wraps kmdapi.APIV1POSTKeyListRequest
func (kcl KMDClient) RenewWalletHandle(walletHandle []byte) (resp kmdapi.APIV1POSTWalletRenewResponse, err error) {
	req := kmdapi.APIV1POSTWalletRenewRequest{
		WalletHandleToken: string(walletHandle),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// ImportKey wraps kmdapi.APIV1POSTKeyImportRequest
func (kcl KMDClient) ImportKey(walletHandle []byte, secretKey crypto.PrivateKey) (resp kmdapi.APIV1POSTKeyImportResponse, err error) {
	req := kmdapi.APIV1POSTKeyImportRequest{
		WalletHandleToken: string(walletHandle),
		PrivateKey:        secretKey,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// ExportMasterDerivationKey wraps kmdapi.APIV1POSTMasterKeyExportRequest
func (kcl KMDClient) ExportMasterDerivationKey(walletHandle []byte, walletPassword []byte) (resp kmdapi.APIV1POSTMasterKeyExportResponse, err error) {
	req := kmdapi.APIV1POSTMasterKeyExportRequest{
		WalletHandleToken: string(walletHandle),
		WalletPassword:    string(walletPassword),
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// SignTransaction wraps kmdapi.APIV1POSTTransactionSignRequest
func (kcl KMDClient) SignTransaction(walletHandle, pw []byte, pk crypto.PublicKey, tx transactions.Transaction) (resp kmdapi.APIV1POSTTransactionSignResponse, err error) {
	txBytes := protocol.Encode(&tx)
	req := kmdapi.APIV1POSTTransactionSignRequest{
		WalletHandleToken: string(walletHandle),
		WalletPassword:    string(pw),
		PublicKey:         pk,
		Transaction:       txBytes,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// SignProgram wraps kmdapi.APIV1POSTProgramSignRequest
func (kcl KMDClient) SignProgram(walletHandle, pw []byte, addr string, data []byte) (resp kmdapi.APIV1POSTProgramSignResponse, err error) {
	req := kmdapi.APIV1POSTProgramSignRequest{
		WalletHandleToken: string(walletHandle),
		WalletPassword:    string(pw),
		Program:           data,
		Address:           addr,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}
