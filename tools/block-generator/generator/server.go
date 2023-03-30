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
	"strings"
	"time"

	"github.com/algorand/go-algorand/tools/block-generator/util"
	"gopkg.in/yaml.v3"
)

func initializeConfigFile(configFile string) (config GenerationConfig, err error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	yaml.Unmarshal(data, &config)
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", help)
	mux.Handle("/v2/blocks/", blocksMiddleware(http.HandlerFunc(getBlockHandler(gen))))
	mux.HandleFunc("/v2/accounts/", getAccountHandler(gen))
	mux.HandleFunc("/genesis", getGenesisHandler(gen))
	mux.HandleFunc("/report", getReportHandler(gen))
	mux.HandleFunc("/v2/status/wait-for-block-after/", getStatusWaitHandler(gen))

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
		round, err := parseRound(r.URL.Path)
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

const blockQueryPrefix = "/v2/blocks/"
const blockQueryBlockIdx = len(blockQueryPrefix)
const accountsQueryPrefix = "/v2/accounts/"
const accountsQueryAccountIdx = len(accountsQueryPrefix)

func parseRound(path string) (uint64, error) {
	if !strings.HasPrefix(path, blockQueryPrefix) {
		return 0, fmt.Errorf("not a blocks query: %s", path)
	}

	result := uint64(0)
	pathlen := len(path)

	if pathlen == blockQueryBlockIdx {
		return 0, fmt.Errorf("no block in path")
	}

	for i := blockQueryBlockIdx; i < pathlen; i++ {
		if path[i] < '0' || path[i] > '9' {
			if i == blockQueryBlockIdx {
				return 0, fmt.Errorf("no block in path")
			}
			break
		}
		result = (uint64(10) * result) + uint64(int(path[i])-'0')
	}
	return result, nil
}

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
