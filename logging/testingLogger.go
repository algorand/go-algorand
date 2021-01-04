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
	"testing"
)

// TestLogWriter is an io.Writer that wraps a testing.T (or a testing.B) -- anything written to it gets logged with t.Log(...)
// Being an io.Writer lets us pass it to Logger.SetOutput() in testing code -- this way if we want we can use Go's built-in testing log instead of making a new base.log file for each test.
// As a bonus, the detailed logs produced in a Travis test are now easily accessible and are printed if and only if that particular ttest fails.
type TestLogWriter struct {
	testing.TB
}

func (tb TestLogWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if p[len(p)-1] == '\n' {
		// t.Log() does its own line ending, don't need an extra
		p = p[:len(p)-1]
	}
	tb.Log(string(p))
	return len(p), nil
}

// TestingLog is a test-only convenience function to configure logging for testing
func TestingLog(tb testing.TB) Logger {
	l := NewLogger()
	l.SetLevel(Debug)
	l.SetOutput(TestLogWriter{tb})
	return l
}
