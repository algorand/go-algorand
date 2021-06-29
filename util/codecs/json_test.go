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

package codecs

import (
	"github.com/algorand/go-algorand/testpartitioning"
	"github.com/stretchr/testify/require"
	"testing"
)

type testValue struct {
	Bool   bool
	String string
	Int    int
}

func TestIsDefaultValue(t *testing.T) {
	testpartitioning.PartitionTest(t)

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
