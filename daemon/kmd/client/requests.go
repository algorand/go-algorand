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

package client

import (
	"bytes"
	"fmt"
	"net/http"

	v1 "github.com/algorand/go-algorand/daemon/kmd/api/v1"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/protocol"
)

// DoV1Request accepts a request from kmdapi/requests and
func (kcl KMDClient) DoV1Request(req kmdapi.APIV1Request, resp kmdapi.APIV1Response) error {
	var body []byte

	// Get the path and method for this request type
	reqPath, reqMethod, err := getPathAndMethod(req)
	if err != nil {
		return err
	}

	// Encode the request
	body = protocol.EncodeJSON(req)
	fullPath := fmt.Sprintf("http://%s/%s", kcl.address, reqPath)
	hreq, err := http.NewRequest(reqMethod, fullPath, bytes.NewReader(body))
	if err != nil {
		return err
	}

	// Add the auth token
	hreq.Header.Add(v1.KMDTokenHeader, kcl.apiToken)

	// Send the request
	hresp, err := kcl.httpClient.Do(hreq)
	if err != nil {
		return err
	}

	// Decode the response object
	decoder := protocol.NewJSONDecoder(hresp.Body)
	err = decoder.Decode(resp)
	hresp.Body.Close()
	if err != nil {
		return err
	}

	// Check if this was an error response
	err = resp.GetError()
	if err != nil {
		return err
	}

	return nil
}

// getPathAndMethod infers the request path and method from the request type
func getPathAndMethod(req kmdapi.APIV1Request) (reqPath string, reqMethod string, err error) {
	switch req.(type) {
	default:
		err = fmt.Errorf("unknown request type")
	case kmdapi.VersionsRequest:
		reqPath = "versions"
		reqMethod = "GET"
	case kmdapi.APIV1GETWalletsRequest:
		reqPath = "v1/wallets"
		reqMethod = "GET"
	case kmdapi.APIV1POSTWalletRequest:
		reqPath = "v1/wallet"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletInitRequest:
		reqPath = "v1/wallet/init"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletReleaseRequest:
		reqPath = "v1/wallet/release"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletRenewRequest:
		reqPath = "v1/wallet/renew"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletRenameRequest:
		reqPath = "v1/wallet/rename"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletInfoRequest:
		reqPath = "v1/wallet/info"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMasterKeyExportRequest:
		reqPath = "v1/master-key/export"
		reqMethod = "POST"
	case kmdapi.APIV1POSTKeyImportRequest:
		reqPath = "v1/key/import"
		reqMethod = "POST"
	case kmdapi.APIV1POSTKeyExportRequest:
		reqPath = "v1/key/export"
		reqMethod = "POST"
	case kmdapi.APIV1POSTKeyRequest:
		reqPath = "v1/key"
		reqMethod = "POST"
	case kmdapi.APIV1DELETEKeyRequest:
		reqPath = "v1/key"
		reqMethod = "DELETE"
	case kmdapi.APIV1POSTKeyListRequest:
		reqPath = "v1/key/list"
		reqMethod = "POST"
	case kmdapi.APIV1POSTProgramSignRequest:
		reqPath = "v1/program/sign"
		reqMethod = "POST"
	case kmdapi.APIV1POSTTransactionSignRequest:
		reqPath = "v1/transaction/sign"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigListRequest:
		reqPath = "v1/multisig/list"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigImportRequest:
		reqPath = "v1/multisig/import"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigExportRequest:
		reqPath = "v1/multisig/export"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigTransactionSignRequest:
		reqPath = "v1/multisig/sign"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigProgramSignRequest:
		reqPath = "v1/multisig/signprogram"
		reqMethod = "POST"
	case kmdapi.APIV1DELETEMultisigRequest:
		reqPath = "v1/multisig"
		reqMethod = "DELETE"
	}
	return
}
