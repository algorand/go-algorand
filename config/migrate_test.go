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

package config

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestMigrate_FieldDefaultForVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	localType := reflect.TypeOf(Local{})
	for fieldNum := 0; fieldNum < localType.NumField(); fieldNum++ {
		field := localType.Field(fieldNum)

		// make sure Version field is in all local versions
		// make sure MaxConnectionsPerIP absent in 0, 1, 2 and present in 3 and later
		if field.Name == "Version" || field.Name == "MaxConnectionsPerIP" {
			for i := 0; i <= 2; i++ {
				defaultValue, ok := getFieldDefaultForVersion(field, uint32(i))
				if field.Name == "Version" {
					require.True(t, ok)
					require.Equal(t, strconv.Itoa(i), defaultValue)
				}
				if field.Name == "MaxConnectionsPerIP" {
					require.False(t, ok)
					require.Equal(t, "", defaultValue)
				}
			}
			for i := 3; i <= int(getLatestConfigVersion()); i++ {
				defaultValue, ok := getFieldDefaultForVersion(field, uint32(i))
				if field.Name == "Version" {
					require.True(t, ok)
					require.Equal(t, strconv.Itoa(i), defaultValue)
				}
				if field.Name == "MaxConnectionsPerIP" {
					require.True(t, ok)
					require.NotEqual(t, "", defaultValue)
					if i < 27 {
						require.Equal(t, "30", defaultValue)
					} else if i >= 27 && i < 35 {
						require.Equal(t, "15", defaultValue)
					} else if i >= 35 {
						require.Equal(t, "8", defaultValue)
					}
				}
			}
		}
	}
}

// TestMigrate_VersionedLocalInstance makes sure that the versioned local instance
// has the expected fields and default values for each version (by sampling some)
func TestMigrate_VersionedLocalInstance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	v0 := getVersionedLocalInstance(0)
	require.Equal(t, uint64(0), v0.FieldByName("Version").Uint())
	require.Equal(t, uint64(1), v0.FieldByName("BaseLoggerDebugLevel").Uint())
	require.Equal(t, 37, v0.NumField())

	v1 := getVersionedLocalInstance(1)
	require.Equal(t, uint64(1), v1.FieldByName("Version").Uint())
	require.Equal(t, uint64(4), v1.FieldByName("BaseLoggerDebugLevel").Uint())
	require.Equal(t, 37+1, v1.NumField())

	lastVersion := getLatestConfigVersion()
	localType := reflect.TypeOf(Local{})
	vLast := getVersionedLocalInstance(lastVersion)
	require.Equal(t, uint64(lastVersion), vLast.FieldByName("Version").Uint())
	require.Equal(t, uint64(4), vLast.FieldByName("BaseLoggerDebugLevel").Uint())
	require.Equal(t, localType.NumField(), vLast.NumField())
}
