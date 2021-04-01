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

// Package handlers handles and helps specify the algod/api
//
// Currently, server implementation annotations serve
// as the API ground truth. From that, we use go-swagger
// to generate a swagger spec.
//
// IF YOU MODIFY THIS PACKAGE: IMPORTANT
// MAKE SURE YOU REGENERATE THE SWAGGER SPEC (using go:generate)
// MAKE SURE IT VALIDATES
package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/logging"
)

// Response is a generic interface wrapping any data returned by the server.
// We wrap every type in a Response type so that we can swagger annotate them.
//
// Each response must have a Body (a payload). We
// write an interface for this because it better mirrors the
// go-swagger annotation style (which requires swagger colon responses
// to have an embedded body struct of the actual data to be sent. of
// course, they can also have headers and the sort.)
// Anything implementing the Response interface will naturally be
// able to be annotated by swagger:response. This also allows package
// functions to naturally unwrap Response types and send the underlying
// Body through another interface (e.g. an http.ResponseWriter)
type Response interface {
	getBody() interface{}
}

func writeJSON(obj interface{}, w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(obj)
}

// SendJSON is like writeJSON, but it writes to the log instead of returning an error.
// The caller must ensure that no writes to w happen after this function is called.
// Unwraps a Response object and converts it to an HTTP Response.
func SendJSON(obj Response, w http.ResponseWriter, log logging.Logger) {
	w.Header().Set("Content-Type", "application/json")
	err := writeJSON(obj.getBody(), w)
	if err != nil {
		log.Warnf("algod failed to write an object to the response stream: %v", err)
	}
}

// StatusResponse contains the node's status information
//
// swagger:response StatusResponse
type StatusResponse struct {
	// in: body
	Body *v1.NodeStatus
}

func (sr StatusResponse) getBody() interface{} {
	return sr.Body
}

// TransactionIDResponse contains a transaction information
//
// swagger:response TransactionIDResponse
type TransactionIDResponse struct {
	// in: body
	Body *v1.TransactionID
}

func (r TransactionIDResponse) getBody() interface{} {
	return r.Body
}

// AccountInformationResponse contains an account information
//
// swagger:response AccountInformationResponse
type AccountInformationResponse struct {
	// in: body
	Body *v1.Account
}

func (r AccountInformationResponse) getBody() interface{} {
	return r.Body
}

// TransactionResponse contains a transaction information
//
// swagger:response TransactionResponse
type TransactionResponse struct {
	// in: body
	Body *v1.Transaction
}

func (r TransactionResponse) getBody() interface{} {
	return r.Body
}

// TransactionsResponse contains a list of transactions
//
// swagger:response TransactionsResponse
type TransactionsResponse struct {
	// in: body
	Body *v1.TransactionList
}

func (r TransactionsResponse) getBody() interface{} {
	return r.Body
}

// AssetsResponse contains a list of assets
//
// swagger:response AssetsResponse
type AssetsResponse struct {
	// in: body
	Body *v1.AssetList
}

func (r AssetsResponse) getBody() interface{} {
	return r.Body
}

// AssetInformationResponse contains asset information
//
// swagger:response AssetInformationResponse
type AssetInformationResponse struct {
	// in: body
	Body *v1.AssetParams
}

func (r AssetInformationResponse) getBody() interface{} {
	return r.Body
}

// TransactionFeeResponse contains a suggested fee
//
// swagger:response TransactionFeeResponse
type TransactionFeeResponse struct {
	// in: body
	Body *v1.TransactionFee
}

func (r TransactionFeeResponse) getBody() interface{} {
	return r.Body
}

// TransactionParamsResponse contains the parameters for
// constructing a new transaction.
//
// swagger:response TransactionParamsResponse
type TransactionParamsResponse struct {
	// in: body
	Body *v1.TransactionParams
}

func (r TransactionParamsResponse) getBody() interface{} {
	return r.Body
}

// RawBlockResponse contains encoded, raw block information
//
// swagger:ignore
type RawBlockResponse struct {
	// in: body
	Body *v1.RawBlock
}

func (r RawBlockResponse) getBody() interface{} {
	return r.Body
}

// BlockResponse contains block information
//
// swagger:response BlockResponse
type BlockResponse struct {
	// in: body
	Body *v1.Block
}

func (r BlockResponse) getBody() interface{} {
	return r.Body
}

// SupplyResponse contains the ledger supply information
//
// swagger:response SupplyResponse
type SupplyResponse struct {
	// in: body
	Body *v1.Supply
}

func (r SupplyResponse) getBody() interface{} {
	return r.Body
}

/* Errors */

// PendingTransactionsResponse contains a (potentially truncated) list of transactions and
// the total number of transactions currently in the pool.
//
// swagger:response PendingTransactionsResponse
type PendingTransactionsResponse struct {
	// in: body
	Body *v1.PendingTransactions
}

func (r PendingTransactionsResponse) getBody() interface{} {
	return r.Body
}
