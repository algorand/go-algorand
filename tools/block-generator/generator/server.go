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

package generator

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/tools/block-generator/util"
)

// MakeServer configures http handlers. Returns the http server.
func MakeServer(configFile string, addr string) (*http.Server, Generator) {
	noOp := func(next http.Handler) http.Handler {
		return next
	}
	return MakeServerWithMiddleware(0, "", configFile, false, addr, noOp)
}

// BlocksMiddleware is a middleware for the blocks endpoint.
type BlocksMiddleware func(next http.Handler) http.Handler

// MakeServerWithMiddleware allows injecting a middleware for the blocks handler.
// This is needed to simplify tests by stopping block production while validation
// is done on the data.
func MakeServerWithMiddleware(dbround uint64, genesisFile string, configFile string, verbose bool, addr string, blocksMiddleware BlocksMiddleware) (*http.Server, Generator) {
	cfg, err := initializeConfigFile(configFile)
	util.MaybeFail(err, "problem loading config file. Use '--config' or create a config file.")
	var bkGenesis bookkeeping.Genesis
	if genesisFile != "" {
		bkGenesis, err = bookkeeping.LoadGenesisFromFile(genesisFile)
		// TODO: consider using bkGenesis to set cfg.NumGenesisAccounts and cfg.GenesisAccountInitialBalance
		util.MaybeFail(err, "Failed to parse genesis file '%s'", genesisFile)
	}
	gen, err := MakeGenerator(dbround, bkGenesis, cfg, verbose)
	util.MaybeFail(err, "Failed to make generator with config file '%s'", configFile)

	mux := http.NewServeMux()
	mux.HandleFunc("/", help)
	mux.Handle("/v2/blocks/", blocksMiddleware(http.HandlerFunc(getBlockHandler(gen))))
	mux.HandleFunc("/v2/accounts/", getAccountHandler(gen))
	mux.HandleFunc("/genesis", getGenesisHandler(gen))
	mux.HandleFunc("/report", getReportHandler(gen))
	mux.HandleFunc("/v2/status/wait-for-block-after/", getStatusWaitHandler(gen))
	mux.HandleFunc("/v2/ledger/sync/", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/v2/deltas/", getDeltasHandler(gen))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}, gen
}

func help(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Use /v2/blocks/:blocknum: to get a block.")
}

func maybeWriteError(w http.ResponseWriter, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getReportHandler(gen Generator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		maybeWriteError(w, gen.WriteReport(w))
	}
}

func getStatusWaitHandler(gen Generator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		maybeWriteError(w, gen.WriteStatus(w))
	}
}

func getGenesisHandler(gen Generator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		maybeWriteError(w, gen.WriteGenesis(w))
	}
}

func getBlockHandler(gen Generator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// The generator doesn't actually care about the block...
		s, err := parseURL(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		round, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		maybeWriteError(w, gen.WriteBlock(w, round))
	}
}

func getAccountHandler(gen Generator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// The generator doesn't actually care about the block...
		account, err := parseURL(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		maybeWriteError(w, gen.WriteAccount(w, account))
	}
}

func getDeltasHandler(gen Generator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := parseURL(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		round, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		maybeWriteError(w, gen.WriteDeltas(w, round))
	}
}

func parseURL(path string) (string, error) {
	i := strings.LastIndex(path, "/")
	if i == len(path)-1 {
		return "", fmt.Errorf("invalid request path, %s", path)
	}
	if strings.Contains(path[i+1:], "?") {
		return strings.Split(path[i+1:], "?")[0], nil
	}
	return path[i+1:], nil
}
