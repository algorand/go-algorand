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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/algorand/go-algorand/tools/block-generator/util"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

func initializeConfigFile(configFile string) (config GenerationConfig, err error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return
	}
	return
}

// MakeServer configures http handlers. Returns the http server.
func MakeServer(configFile string, addr string) (*http.Server, Generator) {
	noOp := func(next http.Handler) http.Handler {
		return next
	}
	return MakeServerWithMiddleware(configFile, addr, noOp)
}

// BlocksMiddleware is a middleware for the blocks endpoint.
type BlocksMiddleware func(next http.Handler) http.Handler

// MakeServerWithMiddleware allows injecting a middleware for the blocks handler.
// This is needed to simplify tests by stopping block production while validation
// is done on the data.
func MakeServerWithMiddleware(configFile string, addr string, blocksMiddleware BlocksMiddleware) (*http.Server, Generator) {
	config, err := initializeConfigFile(configFile)
	util.MaybeFail(err, "problem loading config file. Use '--config' or create a config file.")

	gen, err := MakeGenerator(config)
	util.MaybeFail(err, "Failed to make generator with config file '%s'", configFile)

	r := mux.NewRouter()
	r.HandleFunc("/", help)
	r.Handle("/v2/blocks/{round}", blocksMiddleware(http.HandlerFunc(getBlockHandler(gen))))
	r.HandleFunc("/v2/accounts/", getAccountHandler(gen))
	r.HandleFunc("/genesis", getGenesisHandler(gen))
	r.HandleFunc("/report", getReportHandler(gen))
	r.HandleFunc("/v2/status/wait-for-block-after/", getStatusWaitHandler(gen))
	r.HandleFunc("/v2/ledger/sync/", func(w http.ResponseWriter, r *http.Request) {})
	r.HandleFunc("/v2/deltas/{round}", getDeltasHandler(gen))

	return &http.Server{
		Addr:              addr,
		Handler:           r,
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
		vars := mux.Vars(r)
		param, ok := vars["round"]
		if !ok {
			http.Error(w, "round missing", http.StatusBadRequest)
			return
		}
		round, err := strconv.ParseUint(param, 10, 64)
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
		account, err := parseAccount(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		maybeWriteError(w, gen.WriteAccount(w, account))
	}
}

func getDeltasHandler(gen Generator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		rd, ok := vars["round"]
		if !ok {
			http.Error(w, "round missing", http.StatusBadRequest)
			return
		}
		round, err := strconv.ParseUint(rd, 10, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		maybeWriteError(w, gen.WriteDeltas(w, round))
	}
}

const accountsQueryPrefix = "/v2/accounts/"
const accountsQueryAccountIdx = len(accountsQueryPrefix)

func parseAccount(path string) (string, error) {
	if !strings.HasPrefix(path, accountsQueryPrefix) {
		return "", fmt.Errorf("not a accounts query: %s", path)
	}

	pathlen := len(path)

	if pathlen == accountsQueryAccountIdx {
		return "", fmt.Errorf("no address in path")
	}

	return path[accountsQueryAccountIdx:], nil
}
