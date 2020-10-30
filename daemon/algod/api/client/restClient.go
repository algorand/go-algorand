// Copyright (C) 2019-2020 Algorand, Inc.
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"

	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	privateV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/private"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const (
	authHeader          = "X-Algo-API-Token"
	healthCheckEndpoint = "/health"
	maxRawResponseBytes = 50e6
)

// APIVersion is used to define which server side API version would be used when making http requests to the server
type APIVersion string

const (
	// APIVersionV1 suggests that the RestClient would use v1 calls whenever it's available for the given request.
	APIVersionV1 APIVersion = "v1"
	// APIVersionV2 suggests that the RestClient would use v2 calls whenever it's available for the given request.
	APIVersionV2 APIVersion = "v2"
)

// rawRequestPaths is a set of paths where the body should not be urlencoded
var rawRequestPaths = map[string]bool{
	"/v1/transactions": true,
	"/v2/teal/dryrun":  true,
	"/v2/teal/compile": true,
}

// RestClient manages the REST interface for a calling user.
type RestClient struct {
	serverURL       url.URL
	apiToken        string
	versionAffinity APIVersion
}

// MakeRestClient is the factory for constructing a RestClient for a given endpoint
func MakeRestClient(url url.URL, apiToken string) RestClient {
	return RestClient{
		serverURL:       url,
		apiToken:        apiToken,
		versionAffinity: APIVersionV1,
	}
}

// SetAPIVersionAffinity sets the client affinity to use a specific version of the API
func (client *RestClient) SetAPIVersionAffinity(affinity APIVersion) (previousAffinity APIVersion) {
	previousAffinity = client.versionAffinity
	client.versionAffinity = affinity
	return
}

// extractError checks if the response signifies an error (for now, StatusCode != 200 or StatusCode != 201).
// If so, it returns the error.
// Otherwise, it returns nil.
func extractError(resp *http.Response) error {
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
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
func (client RestClient) submitForm(response interface{}, path string, request interface{}, requestMethod string, encodeJSON bool, decodeJSON bool) error {
	var err error
	queryURL := client.serverURL
	queryURL.Path = path

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

	// Ensure response isn't too large
	resp.Body = http.MaxBytesReader(nil, resp.Body, maxRawResponseBytes)
	defer resp.Body.Close()

	err = extractError(resp)
	if err != nil {
		return err
	}

	if decodeJSON {
		dec := json.NewDecoder(resp.Body)
		return dec.Decode(&response)
	}

	// Response must implement RawResponse
	raw, ok := response.(v1.RawResponse)
	if !ok {
		return fmt.Errorf("can only decode raw response into type implementing v1.RawResponse")
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	raw.SetBytes(bodyBytes)
	return nil
}

// get performs a GET request to the specific path against the server
func (client RestClient) get(response interface{}, path string, request interface{}) error {
	return client.submitForm(response, path, request, "GET", false /* encodeJSON */, true /* decodeJSON */)
}

// getRaw behaves identically to get but doesn't json decode the response, and
// the response must implement the v1.RawResponse interface
func (client RestClient) getRaw(response v1.RawResponse, path string, request interface{}) error {
	return client.submitForm(response, path, request, "GET", false /* encodeJSON */, false /* decodeJSON */)
}

// post sends a POST request to the given path with the given request object.
// No query parameters will be sent if request is nil.
// response must be a pointer to an object as post writes the response there.
func (client RestClient) post(response interface{}, path string, request interface{}) error {
	return client.submitForm(response, path, request, "POST", true /* encodeJSON */, true /* decodeJSON */)
}

// Status retrieves the StatusResponse from the running node
// the StatusResponse includes data like the consensus version and current round
// Not supported
func (client RestClient) Status() (response generatedV2.NodeStatusResponse, err error) {
	switch client.versionAffinity {
	case APIVersionV2:
		err = client.get(&response, "/v2/status", nil)
	default:
		var nodeStatus v1.NodeStatus
		err = client.get(&nodeStatus, "/v1/status", nil)
		if err == nil {
			response = fillNodeStatusResponse(nodeStatus)
		}
	}
	return
}

// HealthCheck does a health check on the the potentially running node,
// returning an error if the API is down
func (client RestClient) HealthCheck() error {
	return client.get(nil, "/health", nil)
}

func fillNodeStatusResponse(nodeStatus v1.NodeStatus) generatedV2.NodeStatusResponse {
	return generatedV2.NodeStatusResponse{
		LastRound:                 nodeStatus.LastRound,
		LastVersion:               nodeStatus.LastVersion,
		NextVersion:               nodeStatus.NextVersion,
		NextVersionRound:          nodeStatus.NextVersionRound,
		NextVersionSupported:      nodeStatus.NextVersionSupported,
		TimeSinceLastRound:        uint64(nodeStatus.TimeSinceLastRound),
		CatchupTime:               uint64(nodeStatus.CatchupTime),
		StoppedAtUnsupportedRound: nodeStatus.StoppedAtUnsupportedRound,
	}
}

// StatusAfterBlock waits for a block to occur then returns the StatusResponse after that block
// blocks on the node end
// Not supported
func (client RestClient) StatusAfterBlock(blockNum uint64) (response generatedV2.NodeStatusResponse, err error) {
	switch client.versionAffinity {
	case APIVersionV2:
		err = client.get(&response, fmt.Sprintf("/v2/status/wait-for-block-after/%d", blockNum), nil)
	default:
		var nodeStatus v1.NodeStatus
		err = client.get(&nodeStatus, fmt.Sprintf("/v1/status/wait-for-block-after/%d", blockNum), nil)
		if err == nil {
			response = fillNodeStatusResponse(nodeStatus)
		}
	}

	return
}

type pendingTransactionsParams struct {
	Max uint64 `url:"max"`
}

// GetPendingTransactions asks algod for a snapshot of current pending txns on the node, bounded by maxTxns.
// If maxTxns = 0, fetches as many transactions as possible.
func (client RestClient) GetPendingTransactions(maxTxns uint64) (response v1.PendingTransactions, err error) {
	err = client.get(&response, fmt.Sprintf("/v1/transactions/pending"), pendingTransactionsParams{maxTxns})
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
	err = client.get(&response, "/v1/ledger/supply", nil)
	return
}

type transactionsByAddrParams struct {
	FirstRound uint64 `url:"firstRound"`
	LastRound  uint64 `url:"lastRound"`
	Max        uint64 `url:"max"`
}

type assetsParams struct {
	AssetIdx uint64 `url:"assetIdx"`
	Max      uint64 `url:"max"`
}

type appsParams struct {
	AppIdx uint64 `url:"appIdx"`
	Max    uint64 `url:"max"`
}

type rawblockParams struct {
	Raw uint64 `url:"raw"`
}

type rawAccountParams struct {
	Format string `url:"format"`
}

// TransactionsByAddr returns all transactions for a PK [addr] in the [first,
// last] rounds range.
func (client RestClient) TransactionsByAddr(addr string, first, last, max uint64) (response v1.TransactionList, err error) {
	err = client.get(&response, fmt.Sprintf("/v1/account/%s/transactions", addr), transactionsByAddrParams{first, last, max})
	return
}

// AssetInformation gets the AssetInformationResponse associated with the passed asset index
func (client RestClient) AssetInformation(index uint64) (response v1.AssetParams, err error) {
	err = client.get(&response, fmt.Sprintf("/v1/asset/%d", index), nil)
	return
}

// Assets gets up to max assets with maximum asset index assetIdx
func (client RestClient) Assets(assetIdx, max uint64) (response v1.AssetList, err error) {
	err = client.get(&response, "/v1/assets", assetsParams{assetIdx, max})
	return
}

// AssetInformationV2 gets the AssetInformationResponse associated with the passed asset index
func (client RestClient) AssetInformationV2(index uint64) (response generatedV2.Asset, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/assets/%d", index), nil)
	return
}

// ApplicationInformation gets the ApplicationInformationResponse associated
// with the passed application index
func (client RestClient) ApplicationInformation(index uint64) (response generatedV2.Application, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/applications/%d", index), nil)
	return
}

// AccountInformation also gets the AccountInformationResponse associated with the passed address
func (client RestClient) AccountInformation(address string) (response v1.Account, err error) {
	err = client.get(&response, fmt.Sprintf("/v1/account/%s", address), nil)
	return
}

// AccountInformationV2 gets the AccountData associated with the passed address
func (client RestClient) AccountInformationV2(address string) (response generatedV2.Account, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/accounts/%s", address), nil)
	return
}

// Blob represents arbitrary blob of data satisfying v1.RawResponse interface
type Blob []byte

// SetBytes fulfills the RawResponse interface on Blob
func (blob *Blob) SetBytes(b []byte) {
	*blob = b
}

// RawAccountInformationV2 gets the raw AccountData associated with the passed address
func (client RestClient) RawAccountInformationV2(address string) (response []byte, err error) {
	var blob Blob
	err = client.getRaw(&blob, fmt.Sprintf("/v2/accounts/%s", address), rawAccountParams{Format: "msgpack"})
	response = blob
	return
}

// TransactionInformation gets information about a specific transaction involving a specific account
func (client RestClient) TransactionInformation(accountAddress, transactionID string) (response v1.Transaction, err error) {
	transactionID = stripTransaction(transactionID)
	err = client.get(&response, fmt.Sprintf("/v1/account/%s/transaction/%s", accountAddress, transactionID), nil)
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
	err = client.get(&response, fmt.Sprintf("/v1/transactions/pending/%s", transactionID), nil)
	return
}

// SuggestedFee gets the recommended transaction fee from the node
func (client RestClient) SuggestedFee() (response v1.TransactionFee, err error) {
	err = client.get(&response, "/v1/transactions/fee", nil)
	return
}

// SuggestedParams gets the suggested transaction parameters
func (client RestClient) SuggestedParams() (response v1.TransactionParams, err error) {
	err = client.get(&response, "/v1/transactions/params", nil)
	return
}

// SendRawTransaction gets a SignedTxn and broadcasts it to the network
func (client RestClient) SendRawTransaction(txn transactions.SignedTxn) (response v1.TransactionID, err error) {
	err = client.post(&response, "/v1/transactions", protocol.Encode(&txn))
	return
}

// SendRawTransactionGroup gets a SignedTxn group and broadcasts it to the network
func (client RestClient) SendRawTransactionGroup(txgroup []transactions.SignedTxn) error {
	// response is not terribly useful: it's the txid of the first transaction,
	// which can be computed by the client anyway..
	var enc []byte
	for _, tx := range txgroup {
		enc = append(enc, protocol.Encode(&tx)...)
	}

	var response v1.TransactionID
	return client.post(&response, "/v1/transactions", enc)
}

// Block gets the block info for the given round
func (client RestClient) Block(round uint64) (response v1.Block, err error) {
	err = client.get(&response, fmt.Sprintf("/v1/block/%d", round), nil)
	return
}

// RawBlock gets the encoded, raw msgpack block for the given round
func (client RestClient) RawBlock(round uint64) (response v1.RawBlock, err error) {
	err = client.getRaw(&response, fmt.Sprintf("/v1/block/%d", round), rawblockParams{1})
	return
}

// Shutdown requests the node to shut itself down
func (client RestClient) Shutdown() (err error) {
	response := 1
	err = client.post(&response, "/v2/shutdown", nil)
	return
}

// AbortCatchup aborts the currently running catchup
func (client RestClient) AbortCatchup(catchpointLabel string) (response privateV2.CatchpointAbortResponse, err error) {
	err = client.submitForm(&response, fmt.Sprintf("/v2/catchup/%s", catchpointLabel), nil, "DELETE", false, true)
	return
}

// Catchup start catching up to the give catchpoint label
func (client RestClient) Catchup(catchpointLabel string) (response privateV2.CatchpointStartResponse, err error) {
	err = client.submitForm(&response, fmt.Sprintf("/v2/catchup/%s", catchpointLabel), nil, "POST", false, true)
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

// Compile compiles the given program and returned the compiled program
func (client RestClient) Compile(program []byte) (compiledProgram []byte, programHash crypto.Digest, err error) {
	var compileResponse generatedV2.CompileResponse
	err = client.submitForm(&compileResponse, "/v2/teal/compile", program, "POST", false, true)
	if err != nil {
		return nil, crypto.Digest{}, err
	}
	compiledProgram, err = base64.StdEncoding.DecodeString(compileResponse.Result)
	if err != nil {
		return nil, crypto.Digest{}, err
	}
	var progAddr basics.Address
	progAddr, err = basics.UnmarshalChecksumAddress(compileResponse.Hash)
	if err != nil {
		return nil, crypto.Digest{}, err
	}
	programHash = crypto.Digest(progAddr)
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

// RawDryrun gets the raw DryrunResponse associated with the passed address
func (client RestClient) RawDryrun(data []byte) (response []byte, err error) {
	var blob Blob
	err = client.submitForm(&blob, "/v2/teal/dryrun", data, "POST", false /* encodeJSON */, false /* decodeJSON */)
	response = blob
	return
}
