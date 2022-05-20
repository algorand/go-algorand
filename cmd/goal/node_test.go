// Copyright (C) 2019-2022 Algorand, Inc.
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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetMissingCatchPointLabel(t *testing.T) {
	tests := []struct {
		name        string
		genesis     string
		catchpoint  string
		expectedErr string
	}{
		{
			"empty catchpoint",
			"",
			"",
			"403 Forbidden",
		},
		{
			"mainnet catchpoint",
			"mainnet",
			"21120000#BGASEIK2J7A2AFAZ4DGEZKNKZ6OSKYLDCX4GQRBGKX3LKC5S5DNA",
			"",
		},
		{
			"betanet catchpoint",
			"betanet",
			"18170000#XIN4FHWSO4UVK2MY5SZAI74VM3OLFWWLUHIJYONPDKQQ5QG4FZHQ",
			"",
		},
		{
			"testnet catchpoint",
			"testnet",
			"21700000#NRZRHIWFFLTOY6UM5YTG7M6XY3QWVGO37UPP66BH2OWHNWNBKOWQ",
			"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 	fmt.Fprintln(w, test.catchpoint)
			// }))
			// defer ts.Close()

			label, err := getMissingCatchPointLabel(test.genesis)

			if test.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr)
			} else {
				require.Equal(t, test.catchpoint, label)
			}
		})
	}
}
