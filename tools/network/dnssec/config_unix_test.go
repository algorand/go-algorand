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

// +build !windows

package dnssec

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfigEmpty(t *testing.T) {
	a := require.New(t)

	s, tm, err := systemConfig(nil)
	a.Error(err)
	a.Empty(s)
	a.Empty(tm)

	b := bytes.NewBuffer(nil)
	s, tm, err = systemConfig(b)
	a.NoError(err)
	a.Empty(s)
	a.NotEmpty(tm)

	b = bytes.NewBuffer([]byte("somedata"))
	s, tm, err = systemConfig(b)
	a.NoError(err)
	a.Empty(s)
	a.NotEmpty(tm)
}

func TestConfig(t *testing.T) {
	a := require.New(t)

	b := bytes.NewBuffer([]byte("nameserver 127.0.0.1\n"))
	s, tm, err := systemConfig(b)
	a.NoError(err)
	a.Equal(1, len(s))
	a.Equal("127.0.0.1:53", string(s[0]))
	a.Greater(uint64(tm), uint64(time.Microsecond))
	a.Less(uint64(tm), uint64(100*time.Second))

	b = bytes.NewBuffer([]byte("nameserver 127.0.0.1\noptions timeout:1"))
	s, tm, err = systemConfig(b)
	a.NoError(err)
	a.Equal(1, len(s))
	a.Equal("127.0.0.1:53", string(s[0]))
	a.Equal(uint64(tm), uint64(time.Second))
}
