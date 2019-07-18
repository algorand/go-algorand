// Copyright (C) 2019 Algorand, Inc.
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"

	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const (
	authHeader           = "X-Algo-API-Token"
	healthCheckEndpoint  = "/health"
	apiVersionPathPrefix = "/v1"
)

// unversionedPaths ais a set of paths that should not be prefixed by the API version
var unversionedPaths = map[string]bool{
	"/versions": true,
	"/health":   true,
}

// rawRequestPaths is a set of paths where the body should not be urlencoded
var rawRequestPaths = map[string]bool{
	"/transactions": true,
}

// RestClient manages the REST interface for a calling user.
type RestClient struct {
	serverURL url.URL
	apiToken  string
}

// MakeRestClient is the factory for constructing a RestClient for a given endpoint
func MakeRestClient(url url.URL, apiToken string) RestClient {
	return RestClient{
		serverURL: url,
		apiToken:  apiToken,
	}
}

// extractError checks if the response signifies an error (for now, StatusCode != 200).
// If so, it returns the error.
// Otherwise, it returns nil.
func extractError(resp *http.Response) error {
	if resp.StatusCode == 200 {
		return nil
	}

	errorBuf, _ := ioutil.ReadAll(resp.Body) // ignore returned error
	return fmt.Errorf("HTTP %v: %s", resp.Status, errorBuf)
}

// stripTransaction gets a transaction of the form "tx-XXXXXXXX" and truncates the "tx-" part, if it starts with "tx-"
func stripTransaction(tx string) string {
	if strings.HasPrefix(tx, "tx-") {
		return strings.SplitAfter(tx, "-")[1]
	}
	return tx
}

// submitForm is a helper used for submitting (ex.) GETs and POSTs to the server
func (client RestClient) submitForm(response interface{}, path string, request interface{}, requestMethod string, encodeJSON bool) error {
	var err error
	queryURL := client.serverURL
	queryURL.Path = path

	// Handle version prefix
	if !unversionedPaths[path] {
		queryURL.Path = strings.Join([]string{apiVersionPathPrefix, path}, "")
	}

	var req *http.Request
	var body io.Reader

	if request != nil {
		if rawRequestPaths[path] {
			reqBytes, ok := request.([]byte)
			if !ok {
				return fmt.Errorf("couldn't decode raw request as bytes")
			}
			body = bytes.NewBuffer(reqBytes)
		} else {
			v, err := query.Values(request)
			if err != nil {
				return err
			}

			queryURL.RawQuery = v.Encode()
			if encodeJSON {
				jsonValue, _ := json.Marshal(request)
				body = bytes.NewBuffer(jsonValue)
			}
		}
	}

	req, err = http.NewRequest(requestMethod, queryURL.String(), body)
	if err != nil {
		return err
	}

	// If we add another endpoint that does not require auth, we should add a
	// requiresAuth argument to submitForm rather than checking here
	if path != healthCheckEndpoint {
		req.Header.Set(authHeader, client.apiToken)
	}

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	err = extractError(resp)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(resp.Body)
	return dec.Decode(&response)
}

// get performs a GET request to the specific path against the server
func (client RestClient) get(response interface{}, path string, request interface{}) error {
	return client.submitForm(response, path, request, "GET", false /* encodeJSON */)
}

// post sends a POST request to the given path with the given request object.
// No query parameters will be sent if request is nil.
// response must be a pointer to an object as post writes the response there.
func (client RestClient) post(response interface{}, path string, request interface{}) error {
	return client.submitForm(response, path, request, "POST", true /* encodeJSON */)
}

// Status retrieves the StatusResponse from the running node
// the StatusResponse includes data like the consensus version and current round
// Not supported
func (client RestClient) Status() (response v1.NodeStatus, err error) {
	err = client.get(&response, "/status", nil)
	return
}

// HealthCheck does a health check on the the potentially running node,
// returning an error if the API is down
func (client RestClient) HealthCheck() error {
	return client.get(nil, "/health", nil)
}

// StatusAfterBlock waits for a block to occur then returns the StatusResponse after that block
// blocks on the node end
// Not supported
func (client RestClient) StatusAfterBlock(blockNum uint64) (response v1.NodeStatus, err error) {
	err = client.get(&response, fmt.Sprintf("/status/wait-for-block-after/%d", blockNum), nil)
	return
}

type pendingTransactionsParams struct {
	Max uint64 `url:"max"`
}

// GetPendingTransactions asks algod for a snapshot of current pending txns on the node, bounded by maxTxns.
// If maxTxns = 0, fetches as many transactions as possible.
func (client RestClient) GetPendingTransactions(maxTxns uint64) (response v1.PendingTransactions, err error) {
	err = client.get(&response, fmt.Sprintf("/transactions/pending"), pendingTransactionsParams{maxTxns})
	return
}

// Versions retrieves the VersionResponse from the running node
// the VersionResponse includes data like version number and genesis ID
func (client RestClient) Versions() (response common.Version, err error) {
	err = client.get(&response, "/versions", nil)
	return
}

// LedgerSupply gets the supply details for the specified node's Ledger
func (client RestClient) LedgerSupply() (response v1.Supply, err error) {
	err = client.get(&response, "/ledger/supply", nil)
	return
}

type transactionsByAddrParams struct {
	FirstRound uint64 `url:"firstRound"`
	LastRound  uint64 `url:"lastRound"`
	Max        uint64 `url:"max"`
}

// TransactionsByAddr returns all transactions for a PK [addr] in the [first,
// last] rounds range.
func (client RestClient) TransactionsByAddr(addr string, first, last, max uint64) (response v1.TransactionList, err error) {
	err = client.get(&response, fmt.Sprintf("/account/%s/transactions", addr), transactionsByAddrParams{first, last, max})
	return
}

// AccountInformation also gets the AccountInformationResponse associated with the passed address
func (client RestClient) AccountInformation(address string) (response v1.Account, err error) {
	err = client.get(&response, fmt.Sprintf("/account/%s", address), nil)
	return
}

// TransactionInformation gets information about a specific transaction involving a specific account
func (client RestClient) TransactionInformation(accountAddress, transactionID string) (response v1.Transaction, err error) {
	transactionID = stripTransaction(transactionID)
	err = client.get(&response, fmt.Sprintf("/account/%s/transaction/%s", accountAddress, transactionID), nil)
	return
}

// PendingTransactionInformation gets information about a recently issued
// transaction.  There are several cases when this might succeed:
//
// - transaction committed (CommittedRound > 0)
// - transaction still in the pool (CommittedRound = 0, PoolError = "")
// - transaction removed from pool due to error (CommittedRound = 0, PoolError != "")
//
// Or the transaction may have happened sufficiently long ago that the
// node no longer remembers it, and this will return an error.
func (client RestClient) PendingTransactionInformation(transactionID string) (response v1.Transaction, err error) {
	transactionID = stripTransaction(transactionID)
	err = client.get(&response, fmt.Sprintf("/transactions/pending/%s", transactionID), nil)
	return
}

// SuggestedFee gets the recommended transaction fee from the node
func (client RestClient) SuggestedFee() (response v1.TransactionFee, err error) {
	err = client.get(&response, "/transactions/fee", nil)
	return
}

// SuggestedParams gets the suggested transaction parameters
func (client RestClient) SuggestedParams() (response v1.TransactionParams, err error) {
	err = client.get(&response, "/transactions/params", nil)
	return
}

// SendRawTransaction gets a SignedTxn and broadcasts it to the network
func (client RestClient) SendRawTransaction(txn transactions.SignedTxn) (response v1.TransactionID, err error) {
	err = client.post(&response, "/transactions", protocol.Encode(txn))
	return
}

// Block gets the block info for the given round
func (client RestClient) Block(round uint64) (response v1.Block, err error) {
	err = client.get(&response, fmt.Sprintf("/block/%d", round), nil)
	return
}

// GetGoRoutines gets a dump of the goroutines from pprof
// Not supported
func (client RestClient) GetGoRoutines(ctx context.Context) (goRoutines string, err error) {
	// issue a "/debug/pprof/goroutine?debug=1" request
	query := make(map[string]string)
	query["debug"] = "1"

	goRoutines, err = client.doGetWithQuery(ctx, "/debug/pprof/goroutine", query)
	return
}

func (client RestClient) doGetWithQuery(ctx context.Context, path string, queryArgs map[string]string) (result string, err error) {
	queryURL := client.serverURL
	queryURL.Path = path

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return
	}
	q := req.URL.Query()
	for k, v := range queryArgs {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()

	req.Header.Set(authHeader, client.apiToken)

	httpClient := http.Client{}
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	err = extractError(resp)
	if err != nil {
		return
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	result = string(bytes)
	return
}
