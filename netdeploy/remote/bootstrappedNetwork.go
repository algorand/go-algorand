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

package remote

import (
	"encoding/json"
	"os"
)

//BootstrappedNetwork contains the specs for generating db files
type BootstrappedNetwork struct {
	NumRounds                 uint64 `json:numRounds`
	RoundTransactionsCount    uint64 `json:roundTransactionsCount`
	GeneratedAccountsCount    uint64 `json:generatedAccountsCount`
	GeneratedAssetsCount      uint64 `json:generatedAssetsCount`
	GeneratedApplicationCount uint64 `json:generatedApplicationCount`
	SourceWalletName          string `json:sourceWalletName`
}

// LoadBootstrappedData loads a bootstrappedFile structure from a json file
func LoadBootstrappedData(file string) (data BootstrappedNetwork, err error) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	err = dec.Decode(&data)
	return data, err
}
