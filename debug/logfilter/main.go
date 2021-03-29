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

// logfilter buffer go test output and make sure to limit the output to only the error-related stuff.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type test struct {
	name         string
	outputBuffer string
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	tests := make(map[string]test)
	currentTestName := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "=== RUN") {
			var testName string
			fmt.Sscanf(line, "=== RUN   %s", &testName)
			currentTestName = testName
			if _, have := tests[currentTestName]; !have {
				tests[currentTestName] = test{name: currentTestName}
			}
			continue
		}
		if strings.HasPrefix(line, "=== CONT") {
			var testName string
			fmt.Sscanf(line, "=== CONT   %s", &testName)
			currentTestName = testName
			if _, have := tests[currentTestName]; !have {
				panic(fmt.Errorf("test %s is missing", currentTestName))
			}
			continue
		}
		if strings.HasPrefix(line, "=== PAUSE") {
			var testName string
			fmt.Sscanf(line, "=== PAUSE   %s", &testName)
			currentTestName = ""
			if _, have := tests[testName]; !have {
				panic(fmt.Errorf("test %s is missing", testName))
			}
			continue
		}
		if idx := strings.Index(line, "--- PASS:"); idx >= 0 {
			var testName string
			fmt.Sscanf(line[idx:], "--- PASS: %s", &testName)
			if _, have := tests[testName]; !have {
				panic(fmt.Errorf("test '%s' is missing, when parsing '%s'", testName, line))
			}
			fmt.Fprintf(os.Stdout, line+"\r\n")
			continue
		}
		if idx := strings.Index(line, "--- FAIL:"); idx >= 0 {
			var testName string
			fmt.Sscanf(line[idx:], "--- FAIL: %s", &testName)
			test, have := tests[testName]
			if !have {
				panic(fmt.Errorf("test %s is missing", testName))
			}
			fmt.Fprintf(os.Stdout, test.outputBuffer+"\r\n")
			fmt.Fprintf(os.Stdout, line+"\r\n")
			continue
		}
		// otherwise, add the line to the current test.
		currentTest := tests[currentTestName]
		currentTest.outputBuffer += "\r\n" + line
		tests[currentTestName] = currentTest
	}

}
