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
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

// LedgerResponseContentType is the HTTP Content-Type header for a raw ledger block
const LedgerResponseContentType = "application/x-algorand-ledger-v2.1"

const ledgerServerMaxBodyLength = 512 // we don't really pass meaningful content here, so 512 bytes should be a safe limit
//const blockServerCatchupRequestBufferSize = 10

// LedgerServiceLedgerPath is the path to register LedgerService as a handler for when using gorilla/mux
// e.g. .Handle(LedgerServiceLedgerPath, &ls)
const LedgerServiceLedgerPath = "/v{version:[0-9.]+}/{genesisID}/ledger/{round:[0-9a-z]+}"

// LedgerService represents the Ledger RPC API
type LedgerService struct {
	ledger        *data.Ledger
	genesisID     string
	net           network.GossipNode
	enableService bool
}

// MakeLedgerService creates a LedgerService around the provider Ledger and registers it with the HTTP router
func MakeLedgerService(config config.Local, ledger *data.Ledger, net network.GossipNode, genesisID string) *LedgerService {
	service := &LedgerService{
		ledger:        ledger,
		genesisID:     genesisID,
		net:           net,
		enableService: config.EnableLedgerService,
	}
	if service.enableService {
		net.RegisterHTTPHandler(LedgerServiceLedgerPath, service)
	}
	return service
}

// Start listening to catchup requests
func (ls *LedgerService) Start() {
}

// Stop servicing catchup requests
func (ls *LedgerService) Stop() {
}

// ServerHTTP returns blocks
// Either /v{version}/block/{round} or ?b={round}&v={version}
// Uses gorilla/mux for path argument parsing.
func (ls *LedgerService) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	versionStr, hasVersionStr := pathVars["version"]
	roundStr, hasRoundStr := pathVars["round"]
	genesisID, hasGenesisID := pathVars["genesisID"]
	if hasVersionStr {
		if versionStr != "1" {
			logging.Base().Debug("http ledger bad version", versionStr)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if hasGenesisID {
		if ls.genesisID != genesisID {
			logging.Base().Debugf("http ledger bad genesisID mine=%#v theirs=%#v", ls.genesisID, genesisID)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		logging.Base().Debug("http ledger no genesisID")
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if (!hasVersionStr) || (!hasRoundStr) {
		// try query arg ?b={round}
		request.Body = http.MaxBytesReader(response, request.Body, ledgerServerMaxBodyLength)
		err := request.ParseForm()
		if err != nil {
			logging.Base().Debug("http ledger parse form err", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		roundStrs, ok := request.Form["b"]
		if !ok || len(roundStrs) != 1 {
			logging.Base().Debug("http ledger bad block id form arg")
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		roundStr = roundStrs[0]
		versionStrs, ok := request.Form["v"]
		if ok {
			if len(versionStrs) == 1 {
				if versionStrs[0] != "1" {
					logging.Base().Debug("http ledger bad version", versionStr)
					response.WriteHeader(http.StatusBadRequest)
					return
				}
			} else {
				logging.Base().Debug("http ledger wrong number of v args", len(versionStrs))
				response.WriteHeader(http.StatusBadRequest)
				return
			}
		} else {
			versionStr = "1"
		}
	}
	round, err := strconv.ParseUint(roundStr, 36, 64)
	if err != nil {
		logging.Base().Debug("http ledger round parse fail", roundStr, err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	cs, err := ls.ledger.GetCatchpointStream(basics.Round(round))
	if err != nil {
		switch err.(type) {
		case ledger.ErrNoEntry:
			// entry cound not be found.
			response.WriteHeader(http.StatusNotFound)
			return
		default:
			// unexpected error.
			logging.Base().Warnf("ServeHTTP : failed to retrieve catchpoint %d %v", round, err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	defer cs.Close()
	response.Header().Set("Content-Type", LedgerResponseContentType)
	requestedCompressedResponse := strings.Contains(request.Header.Get("Accept-Encoding"), "gzip")
	if requestedCompressedResponse {
		response.Header().Set("Content-Encoding", "gzip")
		io.Copy(response, cs)
		return
	}
	decompressedGzip, err := gzip.NewReader(cs)
	if err != nil {
		logging.Base().Warnf("ServeHTTP : failed to decompress catchpoint %d %v", round, err)
		return
	}
	defer decompressedGzip.Close()
	io.Copy(response, decompressedGzip)
}
