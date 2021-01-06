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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/auction"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// The Auction's Console is a module that enables retrieval of the current
// running auction data. It also allows placing bids and deposits.

var (
	log = logging.Base()
)

var am *auction.Tracker
var rc client.RestClient
var debugMode bool

const preferredPort string = ":8081"

const (
	lookback = 10000
)

func init() {
	// Redirecting logs to stdout
	log.SetOutput(os.Stdout)
}

// Helpers for HTTP methods
type status struct {
	Success bool   `json:"success"`
	Err     string `json:"err,omitempty"`
}

func sendJSON(w http.ResponseWriter, obj interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(obj)
	if err != nil {
		log.Error(err)
	}
}

func httpError(w http.ResponseWriter, err error) {
	log.Error(err)
	sendJSON(w, status{
		Success: false,
		Err:     err.Error(),
	})
}

func parseAuctionID(query string) (*auction.SerializedRunningAuction, error) {
	auctionID, err := strconv.ParseUint(query, 10, 64)
	if err != nil {
		log.Errorf("couldn't parse auction ID - %v", err)
		return nil, err
	}

	if _, ok := am.Auctions[auctionID]; !ok {
		log.Errorf("auctionID %v was not found", auctionID)
		return nil, fmt.Errorf("auctionID %v was not found", auctionID)
	}

	return am.Auctions[auctionID], nil
}

// HTTP Handlers

type currentPriceResponse struct {
	Success   bool   `json:"success"`
	AuctionID uint64 `json:"auctionID"`
	Round     uint64 `json:"round"`
	Price     uint64 `json:"price"`
}

// currentPrice returns the auction's current price
func currentPrice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	runningAuction, err := parseAuctionID(mux.Vars(r)["auctionID"])
	if err != nil {
		httpError(w, err)
		return
	}

	queryRound := mux.Vars(r)["round"]
	var rnd uint64

	if queryRound != "" {
		rnd, err = strconv.ParseUint(queryRound, 10, 64)
		if err != nil {
			log.Errorf("couldn't parse query round - %v", err)
			httpError(w, err)
			return
		}
	} else {
		status, err := rc.Status()
		if err != nil {
			log.Errorf("couldn't get status from rest client %v", err)
			httpError(w, err)
			return
		}
		rnd = status.LastRound
	}

	if rnd < runningAuction.Params().FirstRound || rnd > runningAuction.RunningAuction.LastRound() {
		log.Errorf("round %v is not valid for Auction %v", rnd, runningAuction.Params().AuctionID)
		httpError(w, fmt.Errorf("round %v is not valid for Auction %v", rnd, runningAuction.Params().AuctionID))
		return
	}

	price := runningAuction.CurrentPrice(rnd)
	sendJSON(w, currentPriceResponse{
		Success:   true,
		AuctionID: runningAuction.Params().AuctionID,
		Round:     rnd,
		Price:     price,
	})

	return
}

type bidsResponse struct {
	Success bool                 `json:"success"`
	Bids    []auction.RunningBid `json:"bids"`
}

// bids returns the current list of bids.
func bids(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	runningAuction, err := parseAuctionID(mux.Vars(r)["auctionID"])
	if err != nil {
		httpError(w, err)
		return
	}

	bids := runningAuction.Bids()

	// Make sure we encode an empty JSON array for a nil slice
	if bids == nil {
		bids = make([]auction.RunningBid, 0)
	}

	sendJSON(w, bidsResponse{
		Success: true,
		Bids:    bids,
	})
	return
}

type paramsResponse struct {
	Params auction.Params `json:"params"`
}

// params returns the the params of the current auction
func params(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	runningAuction, err := parseAuctionID(mux.Vars(r)["auctionID"])
	if err != nil {
		httpError(w, err)
		return
	}

	p := runningAuction.Params()
	sendJSON(w, paramsResponse{p})
	return
}

type outcomeResponse struct {
	Outcome     auction.BidOutcomes `json:"outcome"`
	OutcomeHash string              `json:"outcomeHash"`
}

// outcomes return the outcomes of a specific auction
func outcomes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	runningAuction, err := parseAuctionID(mux.Vars(r)["auctionID"])
	if err != nil {
		httpError(w, err)
		return
	}

	if runningAuction.Outcome != nil {
		or := outcomeResponse{
			Outcome:     *runningAuction.Outcome,
			OutcomeHash: crypto.HashObj(runningAuction.Outcome).String(),
		}
		sendJSON(w, or)
	} else {
		httpError(w, fmt.Errorf("auction ID %v was not settled yet", runningAuction.Params().AuctionID))
	}

	return
}

type balanceResponse struct {
	Address string `json:"address"`
	Balance uint64 `json:"outcome"`
}

// balance return the balance of a specific address in a specific auction
func balance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	runningAuction, err := parseAuctionID(mux.Vars(r)["auctionID"])
	if err != nil {
		httpError(w, err)
		return
	}

	queryAddress := mux.Vars(r)["addr"]
	addr, err := basics.UnmarshalChecksumAddress(queryAddress)
	if err != nil {
		httpError(w, err)
		return
	}

	amount := runningAuction.Balance(crypto.Digest(addr))
	sendJSON(w, balanceResponse{Address: queryAddress, Balance: amount})

	return
}

type accountStatusResponse struct {
	Address string               `json:"address"`
	Balance uint64               `json:"balance"`
	Bids    []auction.RunningBid `json:"bids"`
}

func accountStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	runningAuction, err := parseAuctionID(mux.Vars(r)["auctionID"])
	if err != nil {
		httpError(w, err)
		return
	}

	queryAddress := mux.Vars(r)["addr"]
	addr, err := basics.UnmarshalChecksumAddress(queryAddress)
	if err != nil {
		httpError(w, err)
		return
	}

	amount := runningAuction.Balance(crypto.Digest(addr))

	// Get Bids
	bids := make([]auction.RunningBid, 0)
	for _, b := range runningAuction.Bids() {
		if b.Bidder == crypto.Digest(addr) {
			bids = append(bids, b)
		}
	}

	sendJSON(w, accountStatusResponse{Address: queryAddress, Balance: amount, Bids: bids})
	return
}

type lastAuctionIDResponse struct {
	AuctionKey basics.Address `json:"auctionKey"`
	AuctionID  uint64         `json:"auctionID"`
}

func lastAuctionID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	id, err := am.LastAuctionID()
	if err != nil {
		httpError(w, err)
	}

	sendJSON(w, lastAuctionIDResponse{
		AuctionKey: am.AuctionKey,
		AuctionID:  id,
	})
	return
}

func main() {
	// Parse flags
	var auctionKey string
	var algodURLStr string
	var apiToken string
	var listenAddr string
	var startRound uint64

	flag.StringVar(&auctionKey, "auctionkey", "", "Auction Key")
	flag.StringVar(&apiToken, "apitoken", "", "REST API Token")
	flag.StringVar(&algodURLStr, "algod", "http://127.0.0.1:8080", "Algorand's API URL")
	flag.StringVar(&listenAddr, "addr", ":8081", "Listening address")
	flag.BoolVar(&debugMode, "debug", false, "Logs debug level info")
	flag.Uint64Var(&startRound, "startround", 0, "Start Round indicates the round from which the console will start to look for auctions messages.")

	flag.Parse()

	if auctionKey == "" || apiToken == "" {
		fmt.Println("auction key and api token are both required")
		os.Exit(1)
	}

	// Create an Algorand client
	algodURL, err := url.Parse(algodURLStr)
	if err != nil {
		fmt.Printf("failed parsing URL: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	// Check if we're in debug mode
	if debugMode {
		log.SetLevel(logging.Debug)
	} else {
		log.SetLevel(logging.Warn)
	}

	rc = client.MakeRestClient(*algodURL, apiToken)

	// Create an auction tracker
	// Get current round
	status, err := rc.Status()
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	var rnd uint64
	if startRound == 0 {
		if status.LastRound > lookback {
			rnd = status.LastRound - lookback
		} else {
			rnd = 0
		}
	} else {
		rnd = startRound
	}

	am, err = auction.MakeTracker(rnd, auctionKey)
	if err != nil {
		fmt.Printf("Failed creating an auction Tracker - %v", err)
		os.Exit(1)
	}

	// Update auction tracker
	go am.LiveUpdate(rc)

	// Register handles
	r := mux.NewRouter()

	r.HandleFunc("/auctions/{auctionID:[0-9]+}/price/{round:[0-9]+}", currentPrice).Methods("GET")
	r.HandleFunc("/auctions/{auctionID:[0-9]+}/bids", bids).Methods("GET")
	r.HandleFunc("/auctions/{auctionID:[0-9]+}/accounts/{addr}/balance", balance).Methods("GET")
	r.HandleFunc("/auctions/{auctionID:[0-9]+}/accounts/{addr}", accountStatus).Methods("GET")
	r.HandleFunc("/auctions/{auctionID:[0-9]+}", params).Methods("GET")
	r.HandleFunc("/auctions/{auctionID:[0-9]+}/outcomes", outcomes).Methods("GET")
	r.HandleFunc("/auctions/last-auction-id", lastAuctionID).Methods("GET")

	err = listenAndServe(listenAddr, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http.ListenAndServe: %v\n", err)
		os.Exit(1)
	}
}

// start listening on for REST request
func listenAndServe(addr string, handler http.Handler) (err error) {

	logging.Base().Infof("Preparing auction console http server with address: %s", addr)

	if addr == "" {
		addr = ":http"
	}

	listener, err := makeListener(addr)

	if err != nil {
		logging.Base().Errorf("Could not start auction console: %v", err)
		os.Exit(1)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	actualAddress := listener.Addr().(*net.TCPAddr).String()
	ipV4Host := "127.0.0.1"
	ipV4Address := fmt.Sprintf("%s:%d", ipV4Host, port)
	pid := os.Getpid()

	logging.Base().Infof("Binding to address: %s with port %d", actualAddress, port)

	pidFile := filepath.Join(".", "auctionconsole.pid")
	netFile := filepath.Join(".", "auctionconsole.net")

	logging.Base().Infof("Writing pid %d to file: %s", pid, pidFile)
	logging.Base().Infof("Writing addr %s to file: %s", ipV4Address, netFile)

	ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0644)
	ioutil.WriteFile(netFile, []byte(fmt.Sprintf("%s\n", ipV4Address)), 0644)

	panic(http.Serve(listener, handler))
}

// helper handles startup of tcp listener
func makeListener(addr string) (net.Listener, error) {
	var listener net.Listener
	var err error
	if (addr == "127.0.0.1:0") || (addr == ":0") {
		// if port 0 is provided, prefer port 8081 first, then fall back to port 0
		preferredAddr := strings.Replace(addr, ":0", preferredPort, -1)
		listener, err = net.Listen("tcp", preferredAddr)
		if err == nil {
			return listener, err
		}
	}
	// err was not nil or :0 was not provided, fall back to originally passed addr
	return net.Listen("tcp", addr)
}
