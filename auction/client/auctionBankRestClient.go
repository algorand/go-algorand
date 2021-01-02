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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/google/go-querystring/query"

	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/logging"
)

//  Auction Bank Rest Client
//
//http.HandleFunc("/create-user", createUser)
//http.HandleFunc("/transfer-in", transferIn)
//http.HandleFunc("/transfer-out", transferOut)
//http.HandleFunc("/account-status", accountStatus)
//http.HandleFunc("/create-auctions", createAuctions)
//http.HandleFunc("/deposit-auction", depositAuction)
//http.HandleFunc("/settle-auction", settleAuction)

//CreateUserQuery is used to create a user
type CreateUserQuery struct {
	Username string `schema:"username"`
}

//StatusQuery is used to learn about a user
type StatusQuery struct {
	Username string `schema:"username"`
}

//StatusResult is the response to a StatusQuery
type StatusResult struct {
	Success bool   `json:"success"`
	Balance uint64 `json:"balance"`
	Pending uint64 `json:"pending"`
}

//TransferInQuery is a request to add currency to a user's balance
type TransferInQuery struct {
	Username string `schema:"username"`
	Amount   uint64 `schema:"amount"`
}

//TransferOutQuery is a request to subtract currency from a user's balance
type TransferOutQuery struct {
	Username string `schema:"username"`
	Amount   uint64 `schema:"amount"`
}

//CreateAuctionsQuery is a request to create a new auction
type CreateAuctionsQuery struct {
	Auction string `schema:"auction"`
}

//DepositAuctionQuery describes a desired Deposit
type DepositAuctionQuery struct {
	Username  string `json:"username"`
	Auction   string `json:"auction"`
	Bidder    string `json:"bidder"`
	AuctionID uint64 `json:"auctionid"`
	Amount    uint64 `json:"amount"`
}

//DepositStatus is returned in response to DepositAuctionQuery, it contains the desired Deposit, signed as a blob
type DepositStatus struct {
	Success           bool               `json:"success"`
	SignedDepositNote client.BytesBase64 `json:"sigdepb64"`
}

//SettleAuctionQuery defines the end of an auction
type SettleAuctionQuery struct {
	AuctionKey        string             `schema:"auction"`
	SigSettlementBlob client.BytesBase64 `schema:"sigsettle"`
	OutcomesBlob      client.BytesBase64 `schema:"outcomes"`
}

// BankRestClient manages the REST interface for a calling Auction Services.
type BankRestClient struct {
	serverURL url.URL
}

// MakeAuctionBankRestClient is the factory for constructing a AuctionRestClient for a given endpoint
func MakeAuctionBankRestClient(url url.URL) BankRestClient {
	return BankRestClient{
		serverURL: url,
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

// submitForm is a helper used for submitting (ex.) GETs and POSTs to the server
func (client BankRestClient) submitForm(response interface{}, path string, request interface{}, requestMethod string, encodeJSON bool) (err error) {
	queryURL := client.serverURL
	queryURL.Path = path

	var v url.Values

	if request != nil {
		if encodeJSON {

			// if encodeJSON is true, marshall the interface to convert to json schema, convert json to map,
			// then and add the map's key value pairs to the query
			var objmap map[string]interface{}

			jsonValue, _ := json.Marshal(request)

			if err := json.Unmarshal(jsonValue, &objmap); err != nil {
				log.Fatal(err)
			}

			v = url.Values{}
			for key, val := range objmap {
				v.Add(key, fmt.Sprintf("%v", val))
			}

		} else {
			v, err = query.Values(request)
		}

		if err != nil {
			logging.Base().Errorf("query.Values(  %+v ) , resulted in error: %+v", request, err)
			return
		}

		queryURL.RawQuery = v.Encode()
	}

	var req *http.Request
	var body io.Reader

	if encodeJSON {
		jsonValue, _ := json.Marshal(request)
		body = bytes.NewBuffer(jsonValue)
		logging.Base().Infof("encodeJSON(  %+v ) , resulted in body: %+v", request, body)
	}

	req, err = http.NewRequest(requestMethod, queryURL.String(), body)
	if err != nil {
		logging.Base().Errorf("query.Values(  %+v ) , resulted in error: %+v", request, err)
		return
	}

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		logging.Base().Errorf("http.NewRequest( %+v ) %+v", req, err)
		return
	}
	logging.Base().Infof("http.NewRequest( %+v ) resp %+v", req, resp)

	if resp != nil {
		defer resp.Body.Close()

		err = extractError(resp)
		if err != nil {
			logging.Base().Errorf("extractError( %+v ) %+v", resp, err)
			return
		}

		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&response)
		if err != nil {
			logging.Base().Errorf("error decoding response body( %+v ) %+v", resp.Body, err)
			return
		}
		return
	}
	// "else" case:
	errMsg := "no errors were experienced in submitFormWithContext but response was somehow nil"
	logging.Base().Warnf(errMsg)
	err = fmt.Errorf(errMsg)
	return
}

// get performs a GET request to the specific path against the server
func (client BankRestClient) get(response interface{}, path string, request interface{}) error {
	return client.submitForm(response, path, request, "GET", false /* encodeJSON */)
}

// post sends a POST request to the given path with the given request object.
// No query parameters will be sent if request is nil.
// response must be a pointer to an object as post writes the response there.
func (client BankRestClient) post(response interface{}, path string, request interface{}) error {
	return client.submitForm(response, path, request, "POST", true /* encodeJSON */)
}

// CreateUser attempts to create a new user within the Auction Bank
func (client BankRestClient) CreateUser(request CreateUserQuery) (err error) {
	err = client.post(nil, "/create-user", request)
	return
}

// TransferIn attempts to transfer value to an account within the Auction Bank
func (client BankRestClient) TransferIn(request TransferInQuery) (err error) {
	err = client.post(nil, "/transfer-in", request)
	return
}

// TransferOut attempts to transfer value from an account within the Auction Bank
func (client BankRestClient) TransferOut(request TransferOutQuery) (err error) {
	err = client.post(nil, "/transfer-out", request)
	return
}

// AccountStatus retrieves the Account status from the Auction Bank instance
func (client BankRestClient) AccountStatus(request StatusQuery) (response StatusResult, err error) {
	err = client.get(&response, "/account-status", request)
	return
}

// CreateAuction attempts to create a new auction within the Auction Bank
func (client BankRestClient) CreateAuction(request CreateAuctionsQuery) (err error) {
	err = client.post(nil, "/create-auctions", request)
	return
}

// DepositAuction attempts to make a deposit within the Auction Bank
func (client BankRestClient) DepositAuction(request DepositAuctionQuery) (response DepositStatus, err error) {
	err = client.post(&response, "/deposit-auction", request)
	return
}

// SettleAuction attempts to settle the current Auction
func (client BankRestClient) SettleAuction(request SettleAuctionQuery) (err error) {
	err = client.post(nil, "/settle-auction", request)
	return
}
