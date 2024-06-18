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

package config

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/s3"
	"github.com/stretchr/testify/require"
)

func TestAlgodVsUpdatedVersions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := []struct {
		major int
		minor int
		build int
	}{
		{major: 1, minor: 1, build: 32111},
		{major: 2, minor: 0, build: 0},
		{major: 3, minor: 13, build: 170018},
		{major: 3, minor: 15, build: 157},
		{major: 3, minor: 16, build: 0},
		{major: 3, minor: 16, build: 100},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d.%d.%d", tt.major, tt.minor, tt.build), func(t *testing.T) {
			version := Version{Major: tt.major, Minor: tt.minor, BuildNumber: tt.build}
			str := version.String()
			ver, err := s3.GetVersionFromName("_" + str)
			require.NoError(t, err)
			require.Equal(t, version.AsUInt64(), ver)
			major, minor, patch, err := s3.GetVersionPartsFromVersion(ver)
			require.NoError(t, err)
			require.Equal(t, uint64(tt.major), major)
			require.Equal(t, uint64(tt.minor), minor)
			require.Equal(t, uint64(tt.build), patch)

		})
	}
}
