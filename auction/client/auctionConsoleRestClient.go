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
	"net/http"
	"net/url"

	"github.com/google/go-querystring/query"

	"github.com/algorand/go-algorand/auction"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// Rest Client for Auction Console API
//
//	r.HandleFunc("/auctions/{auctionID:[0-9]+}/price/{round:[0-9]+}", currentPrice).Methods("GET")
//	r.HandleFunc("/auctions/{auctionID:[0-9]+}/bids", bids).Methods("GET")
//	r.HandleFunc("/auctions/{auctionID:[0-9]+}/accounts/{addr}/balance", balance).Methods("GET")
//	r.HandleFunc("/auctions/{auctionID:[0-9]+}/accounts/{addr}", accountStatus).Methods("GET")
//	r.HandleFunc("/auctions/{auctionID:[0-9]+}", params).Methods("GET")
//	r.HandleFunc("/auctions/{auctionID:[0-9]+}/outcomes", outcomes).Methods("GET")
//	r.HandleFunc("/auctions/last-auction-id", lastAuctionID).Methods("GET")
//

// CurrentPriceResponse describes the auction price for a given auction and round
type CurrentPriceResponse struct {
	Success   bool   `json:"success"`
	AuctionID uint64 `json:"auctionID"`
	Round     uint64 `json:"round"`
	Price     uint64 `json:"price"`
}

// BidsResponse describes the current bids in the auction
type BidsResponse struct {
	Success bool                 `json:"success"`
	Bids    []auction.RunningBid `json:"bids"`
}

// BalanceResponse describes the tracked balance of an address
type BalanceResponse struct {
	Address string `json:"address"`
	Balance uint64 `json:"outcome"`
}

// AccountStatusResponse describes the balance and running bids of an address
type AccountStatusResponse struct {
	Address string               `json:"address"`
	Balance uint64               `json:"balance"`
	Bids    []auction.RunningBid `json:"bids"`
}

// ParamsResponse describes the auction parameters
type ParamsResponse struct {
	Params auction.Params `json:"params"`
}

// OutcomeResponse describes the auction bid outcomes
type OutcomeResponse struct {
	Outcome auction.BidOutcomes `json:"outcome"`
}

// LastAuctionIDResponse describes the ID of the last completed auction
type LastAuctionIDResponse struct {
	AuctionKey basics.Address `json:"auctionKey"`
	AuctionID  uint64         `json:"auctionID"`
}

// ConsoleRestClient manages the REST interface for a calling Auction Services.
type ConsoleRestClient struct {
	serverURL url.URL
}

// MakeAuctionConsoleRestClient is the factory for constructing a AuctionRestClient for a given endpoint
func MakeAuctionConsoleRestClient(url url.URL) ConsoleRestClient {
	return ConsoleRestClient{
		serverURL: url,
	}
}

// submitForm is a helper used for submitting (ex.) GETs and POSTs to the server
func (client ConsoleRestClient) submitForm(response interface{}, path string, request interface{}, requestMethod string, encodeJSON bool) (err error) {

	queryURL := client.serverURL
	queryURL.Path = path

	if request != nil {
		v, err := query.Values(request)
		if err != nil {
			logging.Base().Errorf("Constructing query values (request = %+v ) resulted in error: %+v", request, err)
			return err
		}

		queryURL.RawQuery = v.Encode()
	}

	var req *http.Request
	var body io.Reader

	if encodeJSON {
		jsonValue, _ := json.Marshal(request)
		body = bytes.NewBuffer(jsonValue)
	}

	req, err = http.NewRequest(requestMethod, queryURL.String(), body)
	if err != nil {
		logging.Base().Errorf("Constructing http request (request method = %+v, queryURL = %s, body = %+v ) resulted in error: %+v", requestMethod, queryURL.String(), body, err)
		return err
	}

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)

	if err != nil {
		logging.Base().Errorf("httpClient.Do(%+v): %v", req, err)
		return err
	}

	defer resp.Body.Close()

	err = extractError(resp)
	if err != nil {
		logging.Base().Errorf("request %+v resulted in  Error: %+v", req, err)
		return
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&response)
	if err != nil {
		logging.Base().Errorf("error decoding response %+v, with error: %+v", resp.Body, err)
		return
	}
	return
}

// get performs a GET request to the specific path against the server
func (client ConsoleRestClient) get(response interface{}, path string, request interface{}) error {
	return client.submitForm(response, path, request, "GET", false /* encodeJSON */)
}

// CurrentPrice returns the current price for the given auction id and round
func (client ConsoleRestClient) CurrentPrice(auctionID uint64, round uint64) (response CurrentPriceResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/auctions/%d/price/%d", auctionID, round), nil)
	return
}

// Bids returns the list of bids for the given auction id
func (client ConsoleRestClient) Bids(auctionID uint64) (response BidsResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/auctions/%d/bids", auctionID), nil)
	return
}

// Balance returns the balance for the given auction id and address
func (client ConsoleRestClient) Balance(auctionID uint64, address string) (response BalanceResponse, err error) {
	err = client.get(&response, fmt.Sprintf("auctionID:%d/accounts/%s/balance", auctionID, address), nil)
	return
}

// AccountStatus returns the account status for the given auction id and address
func (client ConsoleRestClient) AccountStatus(auctionID uint64, address string) (response AccountStatusResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/auctions/%d/accounts/%s", auctionID, address), nil)
	return
}

// Params returns the params for the given auction id
func (client ConsoleRestClient) Params(auctionID uint64) (response ParamsResponse, err error) {
	err = client.get(&response, fmt.Sprintf("/auctions/%d", auctionID), nil)
	return
}

// LastAuctionID returns the last auction id
func (client ConsoleRestClient) LastAuctionID() (response LastAuctionIDResponse, err error) {
	err = client.get(&response, "auctions/last-auction-id", nil)
	return
}
