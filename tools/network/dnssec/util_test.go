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

package dnssec

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitZone(t *testing.T) {
	a := require.New(t)
	var res []string
	var err error

	res, err = splitToZones("")
	a.Error(err)

	res, err = splitToZones("com")
	a.Error(err)

	res, err = splitToZones("example.com")
	a.Error(err)

	res, err = splitToZones(".")
	a.NoError(err)
	a.Equal([]string{"."}, res)

	res, err = splitToZones("com.")
	a.NoError(err)
	a.Equal([]string{".", "com."}, res)

	res, err = splitToZones("example.com.")
	a.NoError(err)
	a.Equal([]string{".", "com.", "example.com."}, res)

	res, err = splitToZones("dev.example.com.")
	a.NoError(err)
	a.Equal([]string{".", "com.", "example.com.", "dev.example.com."}, res)
}

func TestParentZone(t *testing.T) {
	a := require.New(t)
	var res string
	var err error

	res, err = getParentZone("")
	a.Error(err)

	res, err = getParentZone("com")
	a.Error(err)

	res, err = getParentZone(".")
	a.Error(err)

	res, err = getParentZone("com.")
	a.NoError(err)
	a.Equal(".", res)

	res, err = getParentZone("example.com.")
	a.NoError(err)
	a.Equal("com.", res)

	res, err = getParentZone("dev.example.com.")
	a.NoError(err)
	a.Equal("example.com.", res)
}
