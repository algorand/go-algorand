// Copyright (C) 2019-2023 Algorand, Inc.
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
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

const (
	authHeader          = "X-Algo-API-Token"
	healthCheckEndpoint = "/health"
	maxRawResponseBytes = 50e6
)

// rawRequestPaths is a set of paths where the body should not be urlencoded
var rawRequestPaths = map[string]bool{
	"/v2/transactions":          true,
	"/v2/transactions/async":    true,
	"/v2/teal/dryrun":           true,
	"/v2/teal/compile":          true,
	"/v2/participation":         true,
	"/v2/transactions/simulate": true,
}

// unauthorizedRequestError is generated when we receive 401 error from the server. This error includes the inner error
// as well as the likely parameters that caused the issue.
type unauthorizedRequestError struct {
	errorString string
	apiToken    string
	url         string
}

// Error format an error string for the unauthorizedRequestError error.
func (e unauthorizedRequestError) Error() string {
	return fmt.Sprintf("Unauthorized request to `%s` when using token `%s` : %s", e.url, e.apiToken, e.errorString)
}

// HTTPError is generated when we receive an unhandled error from the server. This error contains the error string.
type HTTPError struct {
	StatusCode  int
	Status      string
	ErrorString string
}

// Error formats an error string.
func (e HTTPError) Error() string {
	return fmt.Sprintf("HTTP %s: %s", e.Status, e.ErrorString)
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

// filterASCII filter out the non-ascii printable characters out of the given input string.
// It's used as a security qualifier before adding network provided data into an error message.
// The function allows only characters in the range of [32..126], which excludes all the
// control character, new lines, deletion, etc. All the alpha numeric and punctuation characters
// are included in this range.
func filterASCII(unfilteredString string) (filteredString string) {
	for i, r := range unfilteredString {
		if int(r) >= 0x20 && int(r) <= 0x7e {
			filteredString += string(unfilteredString[i])
		}
	}
	return
}

// extractError checks if the response signifies an error (for now, StatusCode != 200 or StatusCode != 201).
// If so, it returns the error.
// Otherwise, it returns nil.
func extractError(resp *http.Response) error {
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		return nil
	}

	errorBuf, _ := io.ReadAll(resp.Body) // ignore returned error
	var errorJSON model.ErrorResponse
	decodeErr := json.Unmarshal(errorBuf, &errorJSON)

	var errorString string
	if decodeErr == nil {
		if errorJSON.Data == nil {
			// There's no additional data, so let's just use the message
			errorString = errorJSON.Message
		} else {
			// There's additional data, so let's re-encode the JSON response to show everything.
			// We do this because the original response is likely encoded with escapeHTML=true, but
			// since this isn't a webpage that extra encoding is not preferred.
			var buffer strings.Builder
			enc := json.NewEncoder(&buffer)
			enc.SetEscapeHTML(false)
			encErr := enc.Encode(errorJSON)
			if encErr != nil {
				// This really shouldn't happen, but if it does let's default to errorBuff
				errorString = string(errorBuf)
			} else {
				errorString = buffer.String()
			}
		}
	} else {
		errorString = string(errorBuf)
	}
	errorString = filterASCII(errorString)

	if resp.StatusCode == http.StatusUnauthorized {
		apiToken := resp.Request.Header.Get(authHeader)
		return unauthorizedRequestError{errorString, apiToken, resp.Request.URL.String()}
	}

	return HTTPError{StatusCode: resp.StatusCode, Status: resp.Status, ErrorString: errorString}
}

// stripTransaction gets a transaction of the form "tx-XXXXXXXX" and truncates the "tx-" part, if it starts with "tx-"
func stripTransaction(tx string) string {
	if strings.HasPrefix(tx, "tx-") {
		return strings.SplitAfter(tx, "-")[1]
	}
	return tx
}

// RawResponse is fulfilled by responses that should not be decoded as json
type RawResponse interface {
	SetBytes([]byte)
}

// mergeRawQueries merges two raw queries, appending an "&" if both are non-empty
func mergeRawQueries(q1, q2 string) string {
	if q1 == "" || q2 == "" {
		return q1 + q2
	}
	return q1 + "&" + q2
}

// submitForm is a helper used for submitting (ex.) GETs and POSTs to the server
// if expectNoContent is true, then it is expected that the response received will have a content length of zero
func (client RestClient) submitForm(
	response interface{}, path string, params interface{}, body interface{},
	requestMethod string, encodeJSON bool, decodeJSON bool, expectNoContent bool) error {

	var err error
	queryURL := client.serverURL
	queryURL.Path = path

	var req *http.Request
	var bodyReader io.Reader
	var v url.Values

	if params != nil {
		v, err = query.Values(params)
		if err != nil {
			return err
		}
	}

	if requestMethod == "POST" && rawRequestPaths[path] {
		reqBytes, ok := body.([]byte)
		if !ok {
			return fmt.Errorf("couldn't decode raw request as bytes")
		}
		bodyReader = bytes.NewBuffer(reqBytes)
	} else if encodeJSON {
		jsonValue, _ := json.Marshal(params)
		bodyReader = bytes.NewBuffer(jsonValue)
	}

	queryURL.RawQuery = mergeRawQueries(queryURL.RawQuery, v.Encode())

	req, err = http.NewRequest(requestMethod, queryURL.String(), bodyReader)
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

	if expectNoContent {
		if resp.ContentLength == 0 {
			return nil
		}
		return fmt.Errorf("expected empty response but got response of %d bytes", resp.ContentLength)
	}

	if decodeJSON {
		dec := json.NewDecoder(resp.Body)
		return dec.Decode(&response)
	}

	// Response must implement RawResponse
	raw, ok := response.(RawResponse)
	if !ok {
		return fmt.Errorf("can only decode raw response into type implementing RawResponse")
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	raw.SetBytes(bodyBytes)
	return nil
}

// get performs a GET request to the specific path against the server
func (client RestClient) get(response interface{}, path string, request interface{}) error {
	return client.submitForm(response, path, request, nil, "GET", false /* encodeJSON */, true /* decodeJSON */, false)
}

// delete performs a DELETE request to the specific path against the server
// when expectNoContent is true, then no content is expected to be returned from the endpoint
func (client RestClient) delete(response interface{}, path string, request interface{}, expectNoContent bool) error {
	return client.submitForm(response, path, request, nil, "DELETE", false /* encodeJSON */, true /* decodeJSON */, expectNoContent)
}

// getRaw behaves identically to get but doesn't json decode the response, and
// the response must implement the RawResponse interface
func (client RestClient) getRaw(response RawResponse, path string, request interface{}) error {
	return client.submitForm(response, path, request, nil, "GET", false /* encodeJSON */, false /* decodeJSON */, false)
}

// post sends a POST request to the given path with the given request object.
// No query parameters will be sent if request is nil.
// response must be a pointer to an object as post writes the response there.
func (client RestClient) post(response interface{}, path string, params interface{}, body interface{}, expectNoContent bool) error {
	return client.submitForm(response, path, params, body, "POST", true /* encodeJSON */, true /* decodeJSON */, expectNoContent)
}

// Status retrieves the StatusResponse from the running node
// the StatusResponse includes data like the consensus version and current round
// Not supported
func (client RestClient) Status() (response model.NodeStatusResponse, err error) {
	err = client.get(&response, "/v2/status", nil)
	return
}

// WaitForBlock returns the node status after waiting for the given round.
func (client RestClient) WaitForBlock(round basics.Round) (response model.NodeStatusResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/status/wait-for-block-after/%d/", round), nil)
	return
}

// HealthCheck does a health check on the potentially running node,
// returning an error if the API is down
func (client RestClient) HealthCheck() error {
	return client.get(nil, "/health", nil)
}

// ReadyCheck does a readiness check on the potentially running node,
// returning an error if the node is not ready (caught up and healthy)
func (client RestClient) ReadyCheck() error {
	return client.get(nil, "/ready", nil)
}

// StatusAfterBlock waits for a block to occur then returns the StatusResponse after that block
// blocks on the node end
// Not supported
func (client RestClient) StatusAfterBlock(blockNum uint64) (response model.NodeStatusResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/status/wait-for-block-after/%d", blockNum), nil)
	return
}

type pendingTransactionsParams struct {
	Max    uint64 `url:"max"`
	Format string `url:"format"`
}

// GetPendingTransactions asks algod for a snapshot of current pending txns on the node, bounded by maxTxns.
// If maxTxns = 0, fetches as many transactions as possible.
func (client RestClient) GetPendingTransactions(maxTxns uint64) (response model.PendingTransactionsResponse, err error) {
	err = client.get(&response, "/v2/transactions/pending", pendingTransactionsParams{Max: maxTxns, Format: "json"})
	return
}

// GetRawPendingTransactions gets the raw encoded msgpack transactions.
// If maxTxns = 0, fetches as many transactions as possible.
func (client RestClient) GetRawPendingTransactions(maxTxns uint64) (response []byte, err error) {
	var blob Blob
	err = client.getRaw(&blob, "/v2/transactions/pending", pendingTransactionsParams{maxTxns, "msgpack"})
	response = blob
	return
}

// Versions retrieves the VersionResponse from the running node
// the VersionResponse includes data like version number and genesis ID
func (client RestClient) Versions() (response common.Version, err error) {
	err = client.get(&response, "/versions", nil)
	return
}

// LedgerSupply gets the supply details for the specified node's Ledger
func (client RestClient) LedgerSupply() (response model.SupplyResponse, err error) {
	err = client.get(&response, "/v2/ledger/supply", nil)
	return
}

type pendingTransactionsByAddrParams struct {
	Max uint64 `url:"max"`
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

type rawFormat struct {
	Format string `url:"format"`
}

type proofParams struct {
	HashType string `url:"hashtype"`
}

type accountInformationParams struct {
	Format  string `url:"format"`
	Exclude string `url:"exclude"`
}

type catchupParams struct {
	Min uint64 `url:"min"`
}

// PendingTransactionsByAddr returns all the pending transactions for an addr.
func (client RestClient) PendingTransactionsByAddr(addr string, max uint64) (response model.PendingTransactionsResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/accounts/%s/transactions/pending", addr), pendingTransactionsByAddrParams{max})
	return
}

// RawPendingTransactionsByAddr returns all the pending transactions for an addr in raw msgpack format.
func (client RestClient) RawPendingTransactionsByAddr(addr string, max uint64) (response []byte, err error) {
	var blob Blob
	err = client.getRaw(&blob, fmt.Sprintf("/v2/accounts/%s/transactions/pending", addr), pendingTransactionsParams{max, "msgpack"})
	response = blob
	return
}

// AssetInformation gets the AssetInformationResponse associated with the passed asset index
func (client RestClient) AssetInformation(index uint64) (response model.Asset, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/assets/%d", index), nil)
	return
}

// ApplicationInformation gets the ApplicationInformationResponse associated
// with the passed application index
func (client RestClient) ApplicationInformation(index uint64) (response model.Application, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/applications/%d", index), nil)
	return
}

type applicationBoxesParams struct {
	Max uint64 `url:"max,omitempty"`
}

// ApplicationBoxes gets the BoxesResponse associated with the passed application ID
func (client RestClient) ApplicationBoxes(appID uint64, maxBoxNum uint64) (response model.BoxesResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/applications/%d/boxes", appID), applicationBoxesParams{maxBoxNum})
	return
}

type applicationBoxByNameParams struct {
	Name string `url:"name"`
}

// GetApplicationBoxByName gets the BoxResponse associated with the passed application ID and box name
func (client RestClient) GetApplicationBoxByName(appID uint64, name string) (response model.BoxResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/applications/%d/box", appID), applicationBoxByNameParams{name})
	return
}

// AccountInformation gets the AccountData associated with the passed address
func (client RestClient) AccountInformation(address string, includeCreatables bool) (response model.Account, err error) {
	var infoParams accountInformationParams
	if includeCreatables {
		infoParams = accountInformationParams{Exclude: "none", Format: "json"}
	} else {
		infoParams = accountInformationParams{Exclude: "all", Format: "json"}
	}
	err = client.get(&response, fmt.Sprintf("/v2/accounts/%s", address), infoParams)
	return
}

// Blob represents arbitrary blob of data satisfying RawResponse interface
type Blob []byte

// SetBytes fulfills the RawResponse interface on Blob
func (blob *Blob) SetBytes(b []byte) {
	*blob = b
}

// RawAccountInformation gets the raw AccountData associated with the passed address
func (client RestClient) RawAccountInformation(address string) (response []byte, err error) {
	var blob Blob
	err = client.getRaw(&blob, fmt.Sprintf("/v2/accounts/%s", address), rawFormat{Format: "msgpack"})
	response = blob
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
func (client RestClient) PendingTransactionInformation(transactionID string) (response model.PendingTransactionResponse, err error) {
	transactionID = stripTransaction(transactionID)
	err = client.get(&response, fmt.Sprintf("/v2/transactions/pending/%s", transactionID), nil)
	return
}

// RawPendingTransactionInformation gets information about a recently issued transaction in msgpack encoded bytes.
func (client RestClient) RawPendingTransactionInformation(transactionID string) (response []byte, err error) {
	transactionID = stripTransaction(transactionID)
	var blob Blob
	err = client.getRaw(&blob, fmt.Sprintf("/v2/transactions/pending/%s", transactionID), rawFormat{Format: "msgpack"})
	response = blob
	return
}

// AccountApplicationInformation gets account information about a given app.
func (client RestClient) AccountApplicationInformation(accountAddress string, applicationID uint64) (response model.AccountApplicationResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/accounts/%s/applications/%d", accountAddress, applicationID), nil)
	return
}

// RawAccountApplicationInformation gets account information about a given app.
func (client RestClient) RawAccountApplicationInformation(accountAddress string, applicationID uint64) (response []byte, err error) {
	var blob Blob
	err = client.getRaw(&blob, fmt.Sprintf("/v2/accounts/%s/applications/%d", accountAddress, applicationID), rawFormat{Format: "msgpack"})
	response = blob
	return
}

// AccountAssetInformation gets account information about a given app.
func (client RestClient) AccountAssetInformation(accountAddress string, assetID uint64) (response model.AccountAssetResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/accounts/%s/assets/%d", accountAddress, assetID), nil)
	return
}

// RawAccountAssetInformation gets account information about a given app.
func (client RestClient) RawAccountAssetInformation(accountAddress string, assetID uint64) (response []byte, err error) {
	var blob Blob
	err = client.getRaw(&blob, fmt.Sprintf("/v2/accounts/%s/assets/%d", accountAddress, assetID), rawFormat{Format: "msgpack"})
	response = blob
	return
}

// SuggestedParams gets the suggested transaction parameters
func (client RestClient) SuggestedParams() (response model.TransactionParametersResponse, err error) {
	err = client.get(&response, "/v2/transactions/params", nil)
	return
}

// SendRawTransaction gets a SignedTxn and broadcasts it to the network
func (client RestClient) SendRawTransaction(txn transactions.SignedTxn) (response model.PostTransactionsResponse, err error) {
	err = client.post(&response, "/v2/transactions", nil, protocol.Encode(&txn), false)
	return
}

// SendRawTransactionAsync gets a SignedTxn and broadcasts it to the network
func (client RestClient) SendRawTransactionAsync(txn transactions.SignedTxn) (response model.PostTransactionsResponse, err error) {
	err = client.post(&response, "/v2/transactions/async", nil, protocol.Encode(&txn), true)
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

	var response model.PostTransactionsResponse
	return client.post(&response, "/v2/transactions", nil, enc, false)
}

// Block gets the block info for the given round
func (client RestClient) Block(round uint64) (response model.BlockResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/blocks/%d", round), nil)
	return
}

// RawBlock gets the encoded, raw msgpack block for the given round
func (client RestClient) RawBlock(round uint64) (response []byte, err error) {
	var blob Blob
	err = client.getRaw(&blob, fmt.Sprintf("/v2/blocks/%d", round), rawFormat{Format: "msgpack"})
	response = blob
	return
}

// Shutdown requests the node to shut itself down
func (client RestClient) Shutdown() (err error) {
	response := 1
	err = client.post(&response, "/v2/shutdown", nil, nil, false)
	return
}

// AbortCatchup aborts the currently running catchup
func (client RestClient) AbortCatchup(catchpointLabel string) (response model.CatchpointAbortResponse, err error) {
	err = client.submitForm(&response, fmt.Sprintf("/v2/catchup/%s", catchpointLabel), nil, nil, "DELETE", false, true, false)
	return
}

// Catchup start catching up to the give catchpoint label
func (client RestClient) Catchup(catchpointLabel string, minRounds uint64) (response model.CatchpointStartResponse, err error) {
	err = client.submitForm(&response, fmt.Sprintf("/v2/catchup/%s", catchpointLabel), catchupParams{Min: minRounds}, nil, "POST", false, true, false)
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

type compileParams struct {
	SourceMap bool `url:"sourcemap,omitempty"`
}

// Compile compiles the given program and returned the compiled program
func (client RestClient) Compile(program []byte, useSourceMap bool) (compiledProgram []byte, programHash crypto.Digest, sourceMap *logic.SourceMap, err error) {
	var compileResponse model.CompileResponse

	compileRequest := compileParams{SourceMap: useSourceMap}

	err = client.submitForm(&compileResponse, "/v2/teal/compile", compileRequest, program, "POST", false, true, false)
	if err != nil {
		return nil, crypto.Digest{}, nil, err
	}
	compiledProgram, err = base64.StdEncoding.DecodeString(compileResponse.Result)
	if err != nil {
		return nil, crypto.Digest{}, nil, err
	}
	var progAddr basics.Address
	progAddr, err = basics.UnmarshalChecksumAddress(compileResponse.Hash)
	if err != nil {
		return nil, crypto.Digest{}, nil, err
	}
	programHash = crypto.Digest(progAddr)

	// fast exit if we don't want sourcemap, then exit with what we have so far
	if !useSourceMap {
		return
	}

	// if we want sourcemap, then we convert the *map[string]interface{} into *logic.SourceMap
	if compileResponse.Sourcemap == nil {
		return nil, crypto.Digest{}, nil, fmt.Errorf("requesting for sourcemap but get nothing")
	}

	var srcMapInstance logic.SourceMap
	var jsonBytes []byte

	if jsonBytes, err = json.Marshal(*compileResponse.Sourcemap); err != nil {
		return nil, crypto.Digest{}, nil, err
	}
	if err = json.Unmarshal(jsonBytes, &srcMapInstance); err != nil {
		return nil, crypto.Digest{}, nil, err
	}
	sourceMap = &srcMapInstance

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

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	result = string(bytes)
	return
}

// RawDryrun gets the raw DryrunResponse associated with the passed address
func (client RestClient) RawDryrun(data []byte) (response []byte, err error) {
	var blob Blob
	err = client.submitForm(&blob, "/v2/teal/dryrun", nil, data, "POST", false /* encodeJSON */, false /* decodeJSON */, false)
	response = blob
	return
}

// RawSimulateRawTransaction simulates transactions by taking raw request bytes and returns relevant simulation results as raw bytes.
func (client RestClient) RawSimulateRawTransaction(data []byte) (response []byte, err error) {
	var blob Blob
	err = client.submitForm(&blob, "/v2/transactions/simulate", rawFormat{Format: "msgpack"}, data, "POST", false /* encodeJSON */, false /* decodeJSON */, false)
	response = blob
	return
}

// StateProofs gets a state proof that covers a given round
func (client RestClient) StateProofs(round uint64) (response model.StateProofResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/stateproofs/%d", round), nil)
	return
}

// LightBlockHeaderProof gets a Merkle proof for the light block header of a given round.
func (client RestClient) LightBlockHeaderProof(round uint64) (response model.LightBlockHeaderProofResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/blocks/%d/lightheader/proof", round), nil)
	return
}

// TransactionProof gets a Merkle proof for a transaction in a block.
func (client RestClient) TransactionProof(txid string, round uint64, hashType crypto.HashType) (response model.TransactionProofResponse, err error) {
	txid = stripTransaction(txid)
	err = client.get(&response, fmt.Sprintf("/v2/blocks/%d/transactions/%s/proof", round, txid), proofParams{HashType: hashType.String()})
	return
}

// PostParticipationKey sends a key file to the node.
func (client RestClient) PostParticipationKey(file []byte) (response model.PostParticipationResponse, err error) {
	err = client.post(&response, "/v2/participation", nil, file, false)
	return
}

// GetParticipationKeys gets all of the participation keys
func (client RestClient) GetParticipationKeys() (response model.ParticipationKeysResponse, err error) {
	err = client.get(&response, "/v2/participation", nil)
	return
}

// GetParticipationKeyByID gets a single participation key
func (client RestClient) GetParticipationKeyByID(participationID string) (response model.ParticipationKeyResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/participation/%s", participationID), nil)
	return
}

// RemoveParticipationKeyByID removes a particiption key by its ID
func (client RestClient) RemoveParticipationKeyByID(participationID string) (err error) {
	err = client.delete(nil, fmt.Sprintf("/v2/participation/%s", participationID), nil, true)
	return
}

/* Endpoint registered for follower nodes */

// SetSyncRound sets the sync round for the catchup service
func (client RestClient) SetSyncRound(round uint64) (err error) {
	err = client.post(nil, fmt.Sprintf("/v2/ledger/sync/%d", round), nil, nil, true)
	return
}

// UnsetSyncRound deletes the sync round constraint
func (client RestClient) UnsetSyncRound() (err error) {
	err = client.delete(nil, "/v2/ledger/sync", nil, true)
	return
}

// GetSyncRound retrieves the sync round (if set)
func (client RestClient) GetSyncRound() (response model.GetSyncRoundResponse, err error) {
	err = client.get(&response, "/v2/ledger/sync", nil)
	return
}

// GetLedgerStateDelta retrieves the ledger state delta for the round
func (client RestClient) GetLedgerStateDelta(round uint64) (response model.LedgerStateDeltaResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/deltas/%d", round), nil)
	return
}

// GetLedgerStateDeltaForTransactionGroup retrieves the ledger state delta for the txn group specified by the id
func (client RestClient) GetLedgerStateDeltaForTransactionGroup(id string) (response model.LedgerStateDeltaForTransactionGroupResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/deltas/txn/group/%s", id), nil)
	return
}

// GetTransactionGroupLedgerStateDeltasForRound retrieves the ledger state deltas for the txn groups in the specified round
func (client RestClient) GetTransactionGroupLedgerStateDeltasForRound(round uint64) (response model.TransactionGroupLedgerStateDeltasForRoundResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/v2/deltas/%d/txn/group", round), nil)
	return
}

// SetBlockTimestampOffset sets the offset in seconds to add to the block timestamp when in devmode
func (client RestClient) SetBlockTimestampOffset(offset uint64) (err error) {
	err = client.post(nil, fmt.Sprintf("/v2/devmode/blocks/offset/%d", offset), nil, nil, true)
	return
}

// GetBlockTimestampOffset gets the offset in seconds which is being added to devmode blocks
func (client RestClient) GetBlockTimestampOffset() (response model.GetBlockTimeStampOffsetResponse, err error) {
	err = client.get(&response, "/v2/devmode/blocks/offset", nil)
	return
}
