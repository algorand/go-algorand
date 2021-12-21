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
	"io"
	"os"
	"strings"
)

type test struct {
	name         string
	outputBuffer string
}

func logFilter(inFile io.Reader, outFile io.Writer) int {
	scanner := bufio.NewScanner(inFile)

	tests := make(map[string]test)
	currentTestName := ""
	incomingFails := false
	// packageOutputBuffer is used to buffer messages that are package-oriented. i.e. TestMain() generated messages,
	// which are called before any test starts to run.
	packageOutputBuffer := ""
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
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
				fmt.Fprintf(outFile, "%s\r\n%s\r\n", line, packageOutputBuffer)
				packageOutputBuffer = ""
			} else {
				fmt.Fprintf(outFile, line+"\r\n")
				delete(tests, testName)
				currentTestName = ""
			}
			continue
		}
		if idx := strings.Index(line, "--- FAIL:"); idx >= 0 {
			incomingFails = true
			var testName string
			fmt.Sscanf(line[idx:], "--- FAIL: %s", &testName)
			test, have := tests[testName]
			if !have {
				fmt.Fprintf(outFile, "%s\r\n%s\r\n", line, packageOutputBuffer)
				packageOutputBuffer = ""
			} else {
				fmt.Fprintf(outFile, test.outputBuffer+"\r\n")
				fmt.Fprintf(outFile, line+"\r\n")
				test.outputBuffer = ""
				tests[testName] = test
				currentTestName = ""
			}
			continue
		}
		// otherwise, add the line to the current test ( if there is such )
		currentTest, have := tests[currentTestName]
		if have {
			currentTest.outputBuffer += "\r\n" + line
			tests[currentTestName] = currentTest
			continue
		}
		// no current test is only legit if we're PASS, FAIL or package test line summary.
		if line == "PASS" || line == "FAIL" {
			continue
		}
		if strings.HasPrefix(line, "ok  	") {
			fmt.Fprintf(outFile, line+"\r\n")
			packageOutputBuffer = ""
			continue
		}
		if strings.HasPrefix(line, "FAIL	") {
			incomingFails = true
			if len(packageOutputBuffer) > 0 {
				fmt.Fprintf(outFile, line+"...\r\n%s\r\n", packageOutputBuffer)
			}
			packageOutputBuffer = ""
			fmt.Fprintf(outFile, line+"\r\n")
			continue
		}
		// this is package-oriented output
		packageOutputBuffer += line + "\r\n"
	}
	scannerErr := scanner.Err()
	if scannerErr != nil {
		if currentTestName != "" && tests[currentTestName].outputBuffer != "" {
			fmt.Fprint(outFile, tests[currentTestName].outputBuffer)
		}
		fmt.Fprintf(outFile, "logfilter: the following error received on the input stream : %v\r\n", scannerErr)
	}
	if incomingFails {
		return 1
	}
	return 0
}

func main() {
	retCode := logFilter(os.Stdin, os.Stdout)
	os.Exit(retCode)
}
