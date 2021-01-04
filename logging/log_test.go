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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
Since most of the functions are pure wrappers, we don't test them and trust the logrus testing coverage.

Things to test -

TestFileOutputNewLogger -- Tests the input change to Buffer works for a new Logger
TestSetLevelNewLogger -- Tests that the new level doesn't affect the base logger
TestWithFieldsNewLogger - Test functionality on a new Logger
TestSetJSONFormatter - Tests that the output results in JSON Format
*/

func isJSON(s string) bool {
	var js map[string]interface{}
	return json.Unmarshal([]byte(s), &js) == nil

}

func TestFileOutputNewLogger(t *testing.T) {
	a := require.New(t)

	// Create a buffer (mimics a file) for the output
	var bufNewLogger bytes.Buffer

	// Create a new logger
	nl := NewLogger()
	nl.SetOutput(&bufNewLogger)

	nl.Info("Should show up in New logger but not in BaseLogger")

	a.NotContains(bufNewLogger.String(), "Should show up in base logger but not in NewLogger")
	a.Contains(bufNewLogger.String(), "Should show up in New logger but not in BaseLogger")

}

func TestSetLevelNewLogger(t *testing.T) {
	a := require.New(t)

	//Create a buffer (mimics a file) for the output
	var bufNewLogger bytes.Buffer

	//Debug level is info by default
	nl := NewLogger()
	nl.SetOutput(&bufNewLogger)

	nl.Debug("ABC Should not show up")
	nl.Info("CDF Should show up")
	nl.Warn("GHI Should show up")

	// Check the new logger
	a.NotContains(bufNewLogger.String(), "ABC Should not show up")
	a.Contains(bufNewLogger.String(), "CDF Should show up")
	a.Contains(bufNewLogger.String(), "GHI Should show up")
}

func TestWithFieldsNewLogger(t *testing.T) {
	a := require.New(t)

	// Create a buffer (mimics a file) for the output
	var bufNewLogger bytes.Buffer

	nl := NewLogger()
	nl.SetOutput(&bufNewLogger)

	nl.WithFields(Fields{"1": 4, "2": "testNew"}).Info("ABCDEFG")
	a.Regexp("time=\".*\" level=info msg=ABCDEFG 1=4 2=testNew file=log_test.go function=github.com/algorand/go-algorand/logging.TestWithFieldsNewLogger line=\\d+", bufNewLogger.String())
	a.NotRegexp("time=\".*\" level=info msg=ABCDEFG 1=4 2=test file=log_test.go function=github.com/algorand/go-algorand/logging.TestWithFieldsNewLogger line=\\d+", bufNewLogger.String())
}

func TestSetJSONFormatter(t *testing.T) {
	a := require.New(t)

	// Create a buffer (mimics a file) for the output
	var bufNewLogger bytes.Buffer

	nl := NewLogger()
	nl.SetOutput(&bufNewLogger)
	nl.SetJSONFormatter()
	nl.WithFields(Fields{"1": 4, "2": "testNew"}).Info("ABCDEFG")
	a.True(isJSON(bufNewLogger.String()))

}
