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

package rpcs

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/bloom"
)

// TxService provides a service that allows a remote caller to retrieve missing pending transactions
type TxService struct {
	pool            PendingTxAggregate
	pendingTxGroups [][]transactions.SignedTxn
	lastUpdate      int64
	mu              deadlock.RWMutex
	genesisID       string
	log             logging.Logger
	// limit the amount of data we're going to process on this request.
	// the request body should include the bloom filter encoding. This would
	// protect the server from calls that include large body requests.
	maxRequestBodyLength int64
	// cap the response size by stop sending transactions once we reached
	// that size. This allows us to optimize the response size
	// and prevent sending huge responses. The client could make several
	// request to retrieve the remaining trasactions.
	responseSizeLimit int
}

const updateInterval = int64(30)
const responseContentType = "application/x-algorand-ptx-v1"

// calculate the number of bytes that would be consumed when packing a n-bytes buffer into a base64 buffer.
func base64PaddedSize(n int64) int64 {
	return ((n + 2) / 3) * 4
}

func makeTxService(pool PendingTxAggregate, genesisID string, txPoolSize int, responseSizeLimit int) *TxService {
	// figure out how many bytes do we expect the bloom filter to be in the worst case scenario.
	filterBytes := bloom.BinaryMarshalLength(txPoolSize, bloomFilterFalsePositiveRate)
	// since the bloom filter is going to be base64 encoded, account for that as well.
	filterPackedBytes := base64PaddedSize(filterBytes)
	// The http transport add some additional content to the form ( form keys, separators, etc.)
	// we need to account for these if we're trying to match the size in the worst case scenario.
	const httpFormPostingOverhead = 13
	service := &TxService{
		pool:                 pool,
		genesisID:            genesisID,
		log:                  logging.Base(),
		maxRequestBodyLength: filterPackedBytes + httpFormPostingOverhead,
		responseSizeLimit:    responseSizeLimit,
	}
	return service
}

// ServeHTTP returns pending transactions that match a bloom filter
func (txs *TxService) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	genesisID, hasGenesisID := pathVars["genesisID"]
	if hasGenesisID {
		if txs.genesisID != genesisID {
			txs.log.Infof("http block bad genesisID mine=%#v theirs=%#v", txs.genesisID, genesisID)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		txs.log.Debug("http block no genesisID")
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	contentTypes := request.Header["Content-Type"]
	if len(contentTypes) != 1 {
		txs.log.Infof("http request had %d content types headers", len(contentTypes))
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if contentTypes[0] != requestContentType {
		txs.log.Infof("http request has an invalid content type : %v", contentTypes[0])
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	// limit the request body size to maxRequestBodyLength
	request.Body = http.MaxBytesReader(response, request.Body, txs.maxRequestBodyLength)
	err := request.ParseForm()
	if err != nil {
		if strings.Contains(err.Error(), "http: request body too large") {
			txs.log.Infof("http.ParseForm fail due to body length exceed max limit size of %d", txs.maxRequestBodyLength)
		} else {
			txs.log.Infof("http.ParseForm fail: %s", err)
		}
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	bloomFilterText := request.FormValue("bf")
	if len(bloomFilterText) == 0 {
		txs.log.Info("no bloom filter arg")
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	bfblob, err := base64.URLEncoding.DecodeString(bloomFilterText)
	if err != nil {
		txs.log.Infof("filter decode fail: %s", err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	filter, err := bloom.UnmarshalBinary(bfblob)
	if err != nil {
		txs.log.Infof("filter parse fail: %s", err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	txns := txs.getFilteredTxns(filter)
	txblob := protocol.EncodeReflect(txns)
	txs.log.Debugf("sending %d txns in %d bytes", len(txns), len(txblob))
	response.Header().Set("Content-Length", strconv.Itoa(len(txblob)))
	response.Header().Set("Content-Type", responseContentType)
	response.WriteHeader(http.StatusOK)
	_, err = response.Write(txblob)
	if err != nil {
		txs.log.Warnf("http block write failed ", err)
	}
}

func (txs *TxService) getFilteredTxns(bloom *bloom.Filter) (txns []transactions.SignedTxn) {
	pendingTxGroups := txs.updateTxCache()

	missingTxns := make([]transactions.SignedTxn, 0)
	encodedLength := 0
	for _, txgroup := range pendingTxGroups {
		missing := false
		txGroupLength := 0
		for _, tx := range txgroup {
			id := tx.ID()
			if !bloom.Test(id[:]) {
				missing = true
			}
			txGroupLength += tx.GetEncodedLength()
		}
		if missing {
			if encodedLength+txGroupLength > txs.responseSizeLimit {
				break
			}
			for _, tx := range txgroup {
				missingTxns = append(missingTxns, tx)
			}
			encodedLength += txGroupLength
		}
	}
	return missingTxns
}

func (txs *TxService) updateTxCache() (pendingTxGroups [][]transactions.SignedTxn) {
	currentUnixTime := time.Now().Unix()
	txs.mu.RLock()
	if txs.lastUpdate != 0 && txs.lastUpdate+updateInterval >= currentUnixTime {
		// no need to update.
		pendingTxGroups = txs.pendingTxGroups
		txs.mu.RUnlock()
		return
	}
	txs.mu.RUnlock()

	txs.mu.Lock()
	defer txs.mu.Unlock()

	// we need to check again, since we released and took the lock.
	if txs.lastUpdate == 0 || txs.lastUpdate+updateInterval < currentUnixTime {
		// The txs.pool.PendingTxGroups() function allocates a new array on every call. That means that the old
		// array ( if being used ) is still valid. There is no risk of data race here since
		// the txs.pendingTxGroups is a slice (hence a pointer to the array) and not the array itself.
		txs.pendingTxGroups = txs.pool.PendingTxGroups()
		txs.lastUpdate = currentUnixTime
	}
	return txs.pendingTxGroups
}

// TxServiceHTTPPath is the URL path to sync pending transactions from
const TxServiceHTTPPath = "/v1/{genesisID}/txsync"

// RegisterTxService creates a TxService around the provider transaction pool and registers it for RPC with the provided Registrar
func RegisterTxService(pool PendingTxAggregate, registrar Registrar, genesisID string, txPoolSize int, responseSizeLimit int) {
	service := makeTxService(pool, genesisID, txPoolSize, responseSizeLimit)
	registrar.RegisterHTTPHandler(TxServiceHTTPPath, service)
}
