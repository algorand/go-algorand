// Copyright (C) 2019-2025 Algorand, Inc.
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
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
)

type config struct {
	// AccountMnemonic is the mnemonic of the account from which we would like to spend Algos.
	AccountMnemonic string
	// AccountMnemonicList, if provided, is a series of mnemonics for accounts from which to spend Algos.
	AccountMnemonicList []string
	// ClientURL is the url ( such as http://127.0.0.1:8080 ) that would be used to communicate with a node REST endpoint
	ClientURL *url.URL `json:"-"`
	// APIToken is the API token used to communicate with the node.
	APIToken string
	// RoundModulator is the modulator used to determine of the current round is the round at which transactions need to be sent.
	RoundModulator basics.Round
	// RoundOffset is the offset used to determine of the current round is the round at which transactions need to be sent.
	RoundOffset basics.Round
	// Fee is the amount of algos that would be specified in the transaction fee field.
	Fee uint64
	// TxnsToSend is the number of transactions to send in the round where (((round + RoundOffset) % RoundModulator) == 0)
	TxnsToSend int
}

type fileConfig struct {
	config
	ClientURL string `json:"ClientURL"`
}

func loadConfig(configFileName string) (cfg config, err error) {
	var fin io.Reader
	if len(configFileName) > 0 && configFileName[0] == '{' {
		// read -config "{json literal}"
		fin = strings.NewReader(configFileName)
	} else {
		var fd *os.File
		fd, err = os.Open(configFileName)
		if err != nil {
			return config{}, err
		}
		defer fd.Close()
		fin = fd
	}
	jsonDecoder := json.NewDecoder(fin)
	var fileCfg fileConfig
	err = jsonDecoder.Decode(&fileCfg)
	if err == nil {
		cfg = fileCfg.config
		cfg.ClientURL, err = url.Parse(fileCfg.ClientURL)
	}
	return
}
