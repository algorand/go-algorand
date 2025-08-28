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

package fixtures

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// ExpectFixture is a wrapper for running expect tests
type ExpectFixture struct {
	testDir     string
	testDataDir string
	testDirTmp  bool
	t           *testing.T
	testFilter  string
	expectFiles map[string]string
}

func (ef *ExpectFixture) initialize(t *testing.T) (err error) {
	ef.t = t
	ef.testDir = os.Getenv("TESTDIR")
	if ef.testDir == "" {
		ef.testDir = filepath.Join(t.TempDir(), "expect")
		err = os.MkdirAll(ef.testDir, 0755)
		if err != nil {
			ef.t.Errorf("error creating test dir %s, with error %v", ef.testDir, err)
			return
		}
		ef.testDirTmp = true
	}
	ef.testDataDir = os.Getenv("TESTDATADIR")
	if ef.testDataDir == "" {
		ef.testDataDir = filepath.Join(getTestDir(), "testdata")
	}

	ef.testFilter = os.Getenv("TESTFILTER")
	if ef.testFilter == "" {
		ef.testFilter = ".*"
	}
	return
}

func (ef *ExpectFixture) getTestDir(testName string) (workingDir, algoDir string, err error) {
	testName = strings.Replace(testName, ".exp", "", -1)
	workingDir = filepath.Join(ef.testDir, testName)
	err = os.Mkdir(workingDir, 0755)
	if err != nil {
		ef.t.Errorf("error creating test dir %s, with error %v", workingDir, err)
		return
	}
	algoDir = filepath.Join(workingDir, "algod")
	err = os.Mkdir(algoDir, 0755)
	if err != nil {
		ef.t.Errorf("error creating algo dir %s, with error %v", algoDir, err)
		return
	}
	return
}

func (ef *ExpectFixture) removeTestDir(workingDir string) (err error) {
	err = os.RemoveAll(workingDir)
	if err != nil {
		ef.t.Errorf("error removing test dir %s, with error %v", workingDir, err)
		return
	}
	return
}

// MakeExpectTest creates an expect test fixture for the current directory
func MakeExpectTest(t *testing.T) *ExpectFixture {
	if skipExpectTests() {
		t.Skip("Expect tests disabled by environment variables.")
	}

	ef := &ExpectFixture{}
	ef.expectFiles = make(map[string]string) // map expect test to full file name.
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(info.Name(), "Test.exp") {
			ef.expectFiles[info.Name()] = path
		}
		return nil
	})
	require.NoError(SynchronizedTest(t), err)
	err = ef.initialize(t)
	require.NoError(SynchronizedTest(t), err)
	return ef
}

func skipExpectTests() bool {
	// Explicitly enabled.
	if strings.ToUpper(os.Getenv("RUN_EXPECT")) == "TRUE" {
		return false
	}
	if strings.ToUpper(os.Getenv("RUN_EXPECT")) == "FALSE" {
		return true
	}

	// If any of the CI systems didn't set RUN_EXPECT, disable them.
	if strings.ToUpper(os.Getenv("CI")) == "TRUE" {
		return true
	}
	if strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" {
		return true
	}
	if strings.ToUpper(os.Getenv("TRAVIS")) == "TRUE" {
		return true
	}
	if strings.ToUpper(os.Getenv("JENKINS_URL")) != "" {
		return true
	}

	// Implicitly enable for devs running tests.
	return false
}

// Run Process all expect script files with suffix Test.exp within the current directory
func (ef *ExpectFixture) Run() {
	disabledTest := map[string]string{
		"listExpiredParticipationKeyTest.exp": "flaky",
	}
	for testName := range ef.expectFiles {
		if match, _ := regexp.MatchString(ef.testFilter, testName); match {
			ef.t.Run(testName, func(t *testing.T) {
				if reason, ok := disabledTest[testName]; ok {
					t.Skipf("Skipping %s test: %s", testName, reason)
				}
				partitiontest.PartitionTest(t) // Check if this expect test should by run, may SKIP

				syncTest := SynchronizedTest(t)
				workingDir, algoDir, err := ef.getTestDir(testName)
				require.NoError(SynchronizedTest(t), err)
				syncTest.Logf("algoDir: %s\ntestDataDir:%s\n", algoDir, ef.testDataDir)
				cmd := exec.Command("expect", testName, algoDir, ef.testDataDir)
				var outBuf bytes.Buffer
				cmd.Stdout = &outBuf

				// Set stderr to be a file descriptor. In other way Go's exec.Cmd::writerDescriptor
				// attaches a goroutine reading stderr that blocks on io.Copy from stderr.
				// Cmd::CombinedOutput sets stderr to stdout and also blocks.
				// Cmd::Start + Cmd::Wait with manual pipes redirection etc also blocks.
				// Wrapping 'expect' with 'expect "$@" 2>&1' also blocks on stdout reading.
				// Cmd::Output with Cmd::Stderr == nil works but stderr get lost.
				// Using os.File as stderr does not trigger goroutine creation, instead exec.Cmd relies on os.File implementation.
				errFile, err := os.OpenFile(path.Join(workingDir, "stderr.txt"), os.O_CREATE|os.O_RDWR, 0)
				if err != nil {
					syncTest.Logf("failed opening stderr temp file: %s\n", err.Error())
					syncTest.Fail()
				}
				defer errFile.Close() // Close might error but we Sync it before leaving the scope
				cmd.Stderr = errFile

				err = cmd.Run()
				if err != nil {
					var stderr string
					var ferr error
					if ferr = errFile.Sync(); ferr == nil {
						if _, ferr = errFile.Seek(0, 0); ferr == nil {
							if info, ferr := errFile.Stat(); ferr == nil {
								errData := make([]byte, info.Size())
								if _, ferr = errFile.Read(errData); ferr == nil {
									stderr = string(errData)
								}
							}
						}
					}
					if ferr != nil {
						stderr = ferr.Error()
					}
					syncTest.Logf("err running '%s': %s\nstdout: %s\nstderr: %s\n", testName, err, outBuf, stderr)
					syncTest.Fail()
				} else {
					syncTest.Logf("stdout: %s", outBuf.String())
					ef.removeTestDir(workingDir)
				}
			})
		}
	}
}
