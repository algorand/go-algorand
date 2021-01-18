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
	"net/url"
	"os"
)

const configFileName = "loadgenerator.config"

type config struct {
	AccountMnemonic string
	ClientURL       *url.URL `json:"-"`
	APIToken        string
	RoundModulator  uint64
	RoundOffset     uint64
	Fee             uint64
}

type fileConfig struct {
	config
	ClientURL string `json:"ClientURL"`
}

func loadConfig() (cfg config, err error) {
	var fd *os.File
	fd, err = os.Open(configFileName)
	if err != nil {
		return config{}, err
	}
	jsonDecoder := json.NewDecoder(fd)
	var fileCfg fileConfig
	err = jsonDecoder.Decode(&fileCfg)
	if err == nil {
		cfg = fileCfg.config
		cfg.ClientURL, err = url.Parse(fileCfg.ClientURL)
	}
	return
}
