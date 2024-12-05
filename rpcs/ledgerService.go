// Copyright (C) 2019-2024 Algorand, Inc.
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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
)

const (
	// LedgerResponseContentType is the HTTP Content-Type header for a raw ledger block
	LedgerResponseContentType = "application/x-algorand-ledger-v2.1"

	ledgerServerMaxBodyLength = 512 // we don't really pass meaningful content here, so 512 bytes should be a safe limit

	// LedgerServiceLedgerPath is the path to register LedgerService as a handler for when using gorilla/mux
	// e.g. .Handle(LedgerServiceLedgerPath, &ls)
	LedgerServiceLedgerPath = "/v{version:[0-9.]+}/{genesisID}/ledger/{round:[0-9a-z]+}"

	// maxCatchpointFileSize is the default catchpoint file size, if we can't get a concreate number from the ledger.
	maxCatchpointFileSize = 512 * 1024 * 1024 // 512MB

	// expectedWorstUploadSpeedBytesPerSecond defines the worst-case scenario upload speed we expect to get while uploading a catchpoint file
	expectedWorstUploadSpeedBytesPerSecond = 20 * 1024
)

// LedgerForService defines the ledger interface required for the LedgerService
type LedgerForService interface {
	// GetCatchpointStream returns the ReadCloseSize for a request catchpoint round
	GetCatchpointStream(round basics.Round) (ledger.ReadCloseSizer, error)
}

// httpGossipNode is a reduced interface for the gossipNode that only includes the methods needed by the LedgerService
type httpGossipNode interface {
	RegisterHTTPHandler(path string, handler http.Handler)
}

// LedgerService represents the Ledger RPC API
type LedgerService struct {
	// running is non-zero once the service is running, and zero when it's not running. it needs to be at a 32-bit aligned address for RasPI support.
	running       atomic.Int32
	ledger        LedgerForService
	genesisID     string
	net           httpGossipNode
	enableService bool
	stopping      sync.WaitGroup
}

// MakeLedgerService creates a LedgerService around the provider Ledger and registers it with the HTTP router
func MakeLedgerService(config config.Local, ledger LedgerForService, net httpGossipNode, genesisID string) *LedgerService {
	service := &LedgerService{
		ledger:        ledger,
		genesisID:     genesisID,
		net:           net,
		enableService: config.EnableLedgerService,
	}
	// the underlying gorilla/mux doesn't support "unregister", so we're forced to implement it ourselves.
	if service.enableService {
		net.RegisterHTTPHandler(LedgerServiceLedgerPath, service)
	}
	return service
}

// Start listening to catchup requests
func (ls *LedgerService) Start() {
	if ls.enableService {
		ls.running.Store(1)
	}
}

// Stop servicing catchup requests
func (ls *LedgerService) Stop() {
	if ls.enableService {
		logging.Base().Debug("ledger service is stopping")
		defer logging.Base().Debug("ledger service has stopped")

		ls.running.Store(0)
		ls.stopping.Wait()
	}
}

// ServeHTTP returns ledgers for a particular round
// Either /v{version}/{genesisID}/ledger/{round} or ?r={round}&v={version}
// Uses gorilla/mux for path argument parsing.
func (ls *LedgerService) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	ls.stopping.Add(1)
	defer ls.stopping.Done()
	if ls.running.Add(0) == 0 {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	pathVars := mux.Vars(request)
	versionStr, hasVersionStr := pathVars["version"]
	roundStr, hasRoundStr := pathVars["round"]
	genesisID, hasGenesisID := pathVars["genesisID"]
	if hasVersionStr {
		if versionStr != "1" {
			logging.Base().Debugf("LedgerService.ServeHTTP: bad version '%s'", versionStr)
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte(fmt.Sprintf("unsupported version '%s'", versionStr)))
			return
		}
	}
	if hasGenesisID {
		if ls.genesisID != genesisID {
			logging.Base().Debugf("LedgerService.ServeHTTP: bad genesisID mine=%#v theirs=%#v", ls.genesisID, genesisID)
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte(fmt.Sprintf("mismatching genesisID '%s'", genesisID)))
			return
		}
	} else {
		logging.Base().Debug("LedgerService.ServeHTTP: no genesisID")
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("missing genesisID"))
		return
	}
	if (!hasVersionStr) || (!hasRoundStr) {
		// try query arg ?r={round}
		request.Body = http.MaxBytesReader(response, request.Body, ledgerServerMaxBodyLength)
		err := request.ParseForm()
		if err != nil {
			logging.Base().Debugf("LedgerService.ServeHTTP: parse form err : %v", err)
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte(fmt.Sprintf("unable to parse form body : %v", err)))
			return
		}
		roundStrs, ok := request.Form["r"]
		if !ok || len(roundStrs) != 1 {
			logging.Base().Debugf("LedgerService.ServeHTTP: bad round number form arg '%s'", roundStrs)
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte("invalid round number specified in 'r' form argument"))
			return
		}
		roundStr = roundStrs[0]
		versionStrs, ok := request.Form["v"]
		if ok {
			if len(versionStrs) == 1 {
				if versionStrs[0] != "1" {
					logging.Base().Debugf("LedgerService.ServeHTTP: bad version '%s'", versionStr)
					response.WriteHeader(http.StatusBadRequest)
					response.Write([]byte(fmt.Sprintf("unsupported version specified '%s'", versionStrs[0])))
					return
				}
			} else {
				logging.Base().Debugf("LedgerService.ServeHTTP: wrong number of v=%d args", len(versionStrs))
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte(fmt.Sprintf("invalid number of version specified %d", len(versionStrs))))
				return
			}
		}
	}
	round, err := strconv.ParseUint(roundStr, 36, 64)
	if err != nil {
		logging.Base().Debugf("LedgerService.ServeHTTP: round parse fail ('%s'): %v", roundStr, err)
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte(fmt.Sprintf("specified round number could not be parsed using base 36 : %v", err)))
		return
	}
	logging.Base().Infof("LedgerService.ServeHTTP: serving catchpoint round %d", round)
	start := time.Now()
	cs, err := ls.ledger.GetCatchpointStream(basics.Round(round))
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
			// entry cound not be found.
			response.WriteHeader(http.StatusNotFound)
			response.Write([]byte(fmt.Sprintf("catchpoint file for round %d is not available", round)))
			return
		default:
			// unexpected error.
			logging.Base().Warnf("LedgerService.ServeHTTP : failed to retrieve catchpoint %d %v", round, err)
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(fmt.Sprintf("catchpoint file for round %d could not be retrieved due to internal error : %v", round, err)))
			return
		}
	}
	defer cs.Close()
	response.Header().Set("Content-Type", LedgerResponseContentType)
	if request.Method == http.MethodHead {
		response.WriteHeader(http.StatusOK)
		return
	}
	rc := http.NewResponseController(response)
	maxCatchpointFileWritingDuration := 2 * time.Minute

	catchpointFileSize, err := cs.Size()
	if err != nil || catchpointFileSize <= 0 {
		maxCatchpointFileWritingDuration += maxCatchpointFileSize * time.Second / expectedWorstUploadSpeedBytesPerSecond
	} else {
		maxCatchpointFileWritingDuration += time.Duration(catchpointFileSize) * time.Second / expectedWorstUploadSpeedBytesPerSecond
	}
	if wdErr := rc.SetWriteDeadline(time.Now().Add(maxCatchpointFileWritingDuration)); wdErr != nil {
		logging.Base().Warnf("LedgerService.ServeHTTP unable to set connection timeout")
	}

	requestedCompressedResponse := strings.Contains(request.Header.Get("Accept-Encoding"), "gzip")
	if requestedCompressedResponse {
		response.Header().Set("Content-Encoding", "gzip")
		written, err := io.Copy(response, cs)
		if err != nil {
			logging.Base().Infof("LedgerService.ServeHTTP : unable to write compressed catchpoint file for round %d, written bytes %d : %v", round, written, err)
		}
		elapsed := time.Since(start)
		logging.Base().Infof("LedgerService.ServeHTTP: served catchpoint round %d in %d sec", round, int(elapsed.Seconds()))
		return
	}
	decompressedGzip, err := gzip.NewReader(cs)
	if err != nil {
		logging.Base().Warnf("LedgerService.ServeHTTP : failed to decompress catchpoint %d %v", round, err)
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(fmt.Sprintf("catchpoint file for round %d could not be decompressed due to internal error : %v", round, err)))
		return
	}
	defer decompressedGzip.Close()
	written, err := io.Copy(response, decompressedGzip)
	if err != nil {
		logging.Base().Infof("LedgerService.ServeHTTP : unable to write decompressed catchpoint file for round %d, written bytes %d : %v", round, written, err)
	} else {
		elapsed := time.Since(start)
		logging.Base().Infof("LedgerService.ServeHTTP: served catchpoint round %d in %d sec", round, int(elapsed.Seconds()))
	}
}
