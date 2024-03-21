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

package codecs

import (
	"bytes"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

type testValue struct {
	Bool   bool
	String string
	Int    int
}

func TestIsDefaultValue(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)

	v := testValue{
		Bool:   true,
		String: "default",
		Int:    1,
	}
	def := testValue{
		Bool:   true,
		String: "default",
		Int:    2,
	}

	objectValues := createValueMap(v)
	defaultValues := createValueMap(def)

	a.True(isDefaultValue("Bool", objectValues, defaultValues))
	a.True(isDefaultValue("String", objectValues, defaultValues))
	a.False(isDefaultValue("Int", objectValues, defaultValues))
	a.True(isDefaultValue("Missing", objectValues, defaultValues))
}

func TestSaveObjectToFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type TestType struct {
		A uint64
		B string
	}

	obj := TestType{1024, "test"}

	// prettyFormat = false
	{
		filename := path.Join(t.TempDir(), "test.json")
		SaveObjectToFile(filename, obj, false)
		data, err := os.ReadFile(filename)
		require.NoError(t, err)
		expected := `{"A":1024,"B":"test"}
`
		require.Equal(t, expected, string(data))
	}

	// prettyFormat = true
	{
		filename := path.Join(t.TempDir(), "test.json")
		SaveObjectToFile(filename, obj, true)
		data, err := os.ReadFile(filename)
		require.NoError(t, err)
		expected := `{
	"A": 1024,
	"B": "test"
}
`
		require.Equal(t, expected, string(data))
	}

}

func TestWriteNonDefaultValue(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type TestType struct {
		Version       uint32
		Archival      bool
		GossipFanout  int
		NetAddress    string
		ReconnectTime time.Duration
	}

	defaultObject := TestType{
		Version:       1,
		Archival:      true,
		GossipFanout:  50,
		NetAddress:    "Denver",
		ReconnectTime: 60 * time.Second,
	}

	testcases := []struct {
		name   string
		in     TestType
		out    string
		ignore []string
	}{
		{
			name: "all defaults",
			in:   defaultObject,
			out: `{
}`,
		}, {
			name: "some defaults",
			in: TestType{
				Version:       1,
				Archival:      false,
				GossipFanout:  25,
				NetAddress:    "Denver",
				ReconnectTime: 60 * time.Nanosecond,
			},
			out: `{
	"Archival": false,
	"GossipFanout": 25,
	"ReconnectTime": 60
}`,
		}, {
			name:   "ignore",
			in:     defaultObject,
			ignore: []string{"Version", "Archival", "GossipFanout", "NetAddress", "ReconnectTime"},
			out: `{
	"Version": 1,
	"Archival": true,
	"GossipFanout": 50,
	"NetAddress": "Denver",
	"ReconnectTime": 60000000000
}`,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)
			var writer bytes.Buffer
			err := WriteNonDefaultValues(&writer, tc.in, defaultObject, tc.ignore)
			a.NoError(err)
			a.Equal(tc.out, writer.String())
		})
	}
}
