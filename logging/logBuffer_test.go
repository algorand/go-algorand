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

package logging

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type logBufferTestFixture struct {
	lb     *logBuffer
	buffer *bytes.Buffer
	w      io.Writer
}

const testString1 = "^Q&(WE70qw6e67citjy SCjk\r\n~!@<>$%^"
const testString2 = "$*&!@*(!@_!@)#&,../,./,zxc]\\[]\\[[]\\"
const testString3 = "teststring3"

func createFixture(maxDepth uint) logBufferTestFixture {
	fixture := logBufferTestFixture{
		lb:     createLogBuffer(maxDepth),
		buffer: bytes.NewBuffer(nil),
	}

	fixture.w = fixture.lb.wrapOutput(fixture.buffer)
	return fixture
}

func TestLogBufferEmpty(t *testing.T) {
	fixture := createFixture(10)
	require.Equal(t, "", fixture.lb.string())
}

func TestLogBufferString(t *testing.T) {
	fixture := createFixture(10)
	lb := fixture.lb
	w := fixture.w

	require.Equal(t, lb.string(), "")
	fmt.Fprint(w, testString1)
	require.Equal(t, testString1, lb.string())
	require.Equal(t, fixture.buffer.String(), lb.string())
}

func TestLogBufferStrings(t *testing.T) {
	fixture := createFixture(10)
	w := fixture.w
	fmt.Fprint(w, testString1)
	fmt.Fprint(w, testString2)
	fmt.Fprint(w, testString3)

	lb := fixture.lb
	expected := testString1 + testString2 + testString3
	require.Equal(t, expected, lb.string())
	require.Equal(t, expected, fixture.buffer.String())
}

func TestLogBufferZeroMaxDepth(t *testing.T) {
	fixture := createFixture(0)
	w := fixture.w
	fmt.Fprint(w, testString1)
	fmt.Fprint(w, testString2)
	fmt.Fprint(w, testString3)

	// logBuffer should store nothing
	require.Equal(t, "", fixture.lb.string())
}

func TestLogBufferMaxDepth(t *testing.T) {
	fixture := createFixture(2)
	w := fixture.w
	fmt.Fprint(w, testString1)
	fmt.Fprint(w, testString2)
	fmt.Fprint(w, testString3)

	lb := fixture.lb
	expected := testString2 + testString3
	// logBuffer should only store last 2 strings
	require.Equal(t, expected, lb.string())
	// output buffer should still have all 3 strings
	require.Equal(t, testString1+testString2+testString3, fixture.buffer.String())
}

func TestLogBufferTrim(t *testing.T) {
	maxDepth := uint(9)
	entryCount := maxDepth + 2
	lb := createLogBuffer(maxDepth)
	for i := 0; i < int(entryCount); i++ {
		lb.append(fmt.Sprintf("%d", i))
	}

	// Initial count should be maxDepth - filled
	require.Equal(t, maxDepth, lb.used)

	// Trim, then count should be half that (rounded up)
	lb.trim()
	require.Equal(t, (maxDepth+1)/2, lb.used)

	// First entry left should reflect the first half of buffer being trimmed.
	require.Equal(t, fmt.Sprintf("%d", entryCount-((maxDepth+1)/2)), lb.buffer[lb.first])
}
