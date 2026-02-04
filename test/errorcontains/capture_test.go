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

package errorcontains

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	stdsync "sync"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// customError is a custom error type for testing error type capture.
type customError struct {
	code int
	msg  string
}

func (e *customError) Error() string {
	return fmt.Sprintf("code %d: %s", e.code, e.msg)
}

// wrappedError wraps another error for testing unwrap chain capture.
type wrappedError struct {
	msg   string
	inner error
}

func (e *wrappedError) Error() string {
	return fmt.Sprintf("%s: %v", e.msg, e.inner)
}

func (e *wrappedError) Unwrap() error {
	return e.inner
}

// resetSingleton resets the package-level singleton for testing.
func resetSingleton(path string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	if outputFile != nil {
		outputFile.Close()
	}
	outputFile = nil
	initOnce = stdsync.Once{}
	os.Setenv("ERROR_CAPTURE_FILE", path)
}

func TestCaptureError_BasicError(t *testing.T) {
	partitiontest.PartitionTest(t)

	tmpFile, err := os.CreateTemp("", "error_capture_test_*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	resetSingleton(tmpPath)

	testErr := errors.New("test error message")
	CaptureError(t, testErr, "this is a test")

	Close()

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v\ndata: %s", err, data)
	}

	if entry["error_type"] != "*errors.errorString" {
		t.Errorf("expected error_type *errors.errorString, got %v", entry["error_type"])
	}
	if entry["error_msg"] != "test error message" {
		t.Errorf("expected error_msg 'test error message', got %v", entry["error_msg"])
	}
	if entry["user_msg"] != "this is a test" {
		t.Errorf("expected user_msg 'this is a test', got %v", entry["user_msg"])
	}
}

func TestCaptureError_CustomError(t *testing.T) {
	partitiontest.PartitionTest(t)

	tmpFile, err := os.CreateTemp("", "error_capture_test_*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	resetSingleton(tmpPath)

	testErr := &customError{code: 42, msg: "something went wrong"}
	CaptureError(t, testErr)

	Close()

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["error_type"] != "*errorcontains.customError" {
		t.Errorf("expected error_type *errorcontains.customError, got %v", entry["error_type"])
	}
	if entry["error_msg"] != "code 42: something went wrong" {
		t.Errorf("expected error message, got %v", entry["error_msg"])
	}
}

func TestCaptureError_WrappedError(t *testing.T) {
	partitiontest.PartitionTest(t)

	tmpFile, err := os.CreateTemp("", "error_capture_test_*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	resetSingleton(tmpPath)

	inner := errors.New("inner error")
	testErr := &wrappedError{msg: "outer", inner: inner}
	CaptureError(t, testErr)

	Close()

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["error_type"] != "*errorcontains.wrappedError" {
		t.Errorf("expected error_type *errorcontains.wrappedError, got %v", entry["error_type"])
	}
	if entry["unwrapped"] != "*errors.errorString" {
		t.Errorf("expected unwrapped chain, got %v", entry["unwrapped"])
	}
}

func TestErrorCapture_Interface(t *testing.T) {
	partitiontest.PartitionTest(t)

	tmpFile, err := os.CreateTemp("", "error_capture_test_*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	resetSingleton(tmpPath)

	ec := New(t)
	ec.Error(errors.New("interface test"))

	Close()

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(data), "interface test") {
		t.Errorf("expected to find 'interface test' in output: %s", data)
	}
}
