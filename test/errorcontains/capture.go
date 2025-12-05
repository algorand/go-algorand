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

// Package errorcontains provides helpers to capture error details during test
// runs for migration from require.Error to more specific assertions like
// ErrorContains, ErrorIs, or ErrorAs.
package errorcontains

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	outputFile *os.File
	outputMu   sync.Mutex
	initOnce   sync.Once
)

func initOutput() {
	initOnce.Do(func() {
		path := os.Getenv("ERROR_CAPTURE_FILE")
		if path == "" {
			// Use PID in filename to avoid contention between parallel test processes
			path = fmt.Sprintf("/tmp/error_capture.%d.jsonl", os.Getpid())
		}
		var err error
		outputFile, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "errorcontains: failed to open output file %s: %v\n", path, err)
		}
	})
}

// CaptureError is a drop-in replacement for require.Error that captures error
// details to a file for later analysis. It calls t.FailNow() if err is nil.
// The msgAndArgs parameter is passed through like in testify assertions.
func CaptureError(t testing.TB, err error, msgAndArgs ...interface{}) {
	t.Helper()
	captureAndCheck(t, err, true, msgAndArgs...)
}

// CaptureErrorf is like CaptureError but with a formatted message.
func CaptureErrorf(t testing.TB, err error, format string, args ...interface{}) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	captureAndCheck(t, err, true, msg)
}

// CaptureErrorAssert is like CaptureError but uses t.Fail() instead of
// t.FailNow(), matching assert.Error behavior.
func CaptureErrorAssert(t testing.TB, err error, msgAndArgs ...interface{}) {
	t.Helper()
	captureAndCheck(t, err, false, msgAndArgs...)
}

func captureAndCheck(t testing.TB, err error, failNow bool, msgAndArgs ...interface{}) {
	t.Helper()
	initOutput()

	// Get caller info (skip 2: captureAndCheck -> CaptureError -> actual test)
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "unknown"
		line = 0
	}

	// Make file path relative to repo root for readability
	if idx := strings.Index(file, "go-algorand/"); idx != -1 {
		file = file[idx+len("go-algorand/"):]
	}

	var userMsg string
	if len(msgAndArgs) > 0 {
		if s, ok := msgAndArgs[0].(string); ok {
			if len(msgAndArgs) > 1 {
				userMsg = fmt.Sprintf(s, msgAndArgs[1:]...)
			} else {
				userMsg = s
			}
		} else {
			userMsg = fmt.Sprintf("%v", msgAndArgs[0])
		}
	}

	if err == nil {
		// Log that we expected an error but got nil
		writeEntry(t.Name(), file, line, "", "", userMsg, "ERROR_WAS_NIL")
		if failNow {
			t.Fatalf("expected an error but got nil: %s", userMsg)
		} else {
			t.Errorf("expected an error but got nil: %s", userMsg)
		}
		return
	}

	// Capture error details
	errType := reflect.TypeOf(err).String()
	errMsg := err.Error()

	// Check for wrapped errors
	var unwrapped []string
	current := err
	for {
		inner := errors.Unwrap(current)
		if inner == nil {
			break
		}
		unwrapped = append(unwrapped, reflect.TypeOf(inner).String())
		current = inner
	}

	writeEntry(t.Name(), file, line, errType, errMsg, userMsg, strings.Join(unwrapped, " -> "))
}

func writeEntry(testName, file string, line int, errType, errMsg, userMsg, unwrapped string) {
	if outputFile == nil {
		return
	}

	// Escape strings for JSON
	escape := func(s string) string {
		s = strings.ReplaceAll(s, "\\", "\\\\")
		s = strings.ReplaceAll(s, "\"", "\\\"")
		s = strings.ReplaceAll(s, "\n", "\\n")
		s = strings.ReplaceAll(s, "\r", "\\r")
		s = strings.ReplaceAll(s, "\t", "\\t")
		return s
	}

	entry := fmt.Sprintf(`{"test":%q,"file":%q,"line":%d,"error_type":%q,"error_msg":%q,"user_msg":%q,"unwrapped":%q}`+"\n",
		escape(testName), escape(file), line,
		escape(errType), escape(errMsg), escape(userMsg), escape(unwrapped))

	outputMu.Lock()
	defer outputMu.Unlock()
	outputFile.WriteString(entry)
}

// ErrorCapture provides an assertions-style interface like require.New(t).
type ErrorCapture struct {
	t       testing.TB
	failNow bool
}

// New returns an ErrorCapture for require-style usage (fails immediately).
func New(t testing.TB) *ErrorCapture {
	return &ErrorCapture{t: t, failNow: true}
}

// NewAssert returns an ErrorCapture for assert-style usage (continues on failure).
func NewAssert(t testing.TB) *ErrorCapture {
	return &ErrorCapture{t: t, failNow: false}
}

// Error captures error details and fails if err is nil.
func (e *ErrorCapture) Error(err error, msgAndArgs ...interface{}) {
	e.t.Helper()
	captureAndCheck(e.t, err, e.failNow, msgAndArgs...)
}

// Errorf captures error details with a formatted message.
func (e *ErrorCapture) Errorf(err error, format string, args ...interface{}) {
	e.t.Helper()
	msg := fmt.Sprintf(format, args...)
	captureAndCheck(e.t, err, e.failNow, msg)
}

// Close should be called at the end of test runs to ensure all data is flushed.
func Close() {
	outputMu.Lock()
	defer outputMu.Unlock()
	if outputFile != nil {
		outputFile.Close()
		outputFile = nil
	}
}

// Summary generates a summary report from the captured error data.
// This is useful for reviewing the captured errors before migration.
func Summary(inputPath string) (map[string]int, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	// Count occurrences of each error type
	counts := make(map[string]int)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		// Extract error_type from JSON line (simple parsing)
		if idx := strings.Index(line, `"error_type":"`); idx != -1 {
			start := idx + len(`"error_type":"`)
			end := strings.Index(line[start:], `"`)
			if end != -1 {
				errType := line[start : start+end]
				counts[errType]++
			}
		}
	}
	return counts, nil
}

// OutputPath returns the path where error captures are being written.
// Note: when ERROR_CAPTURE_FILE is not set, each test process writes to its
// own file with PID suffix. Use "cat /tmp/error_capture.*.jsonl" to combine.
func OutputPath() string {
	path := os.Getenv("ERROR_CAPTURE_FILE")
	if path == "" {
		path = fmt.Sprintf("/tmp/error_capture.%d.jsonl", os.Getpid())
	}
	return filepath.Clean(path)
}
