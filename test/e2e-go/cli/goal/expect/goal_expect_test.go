// Copyright (C) 2020 Algorand, Inc.
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

package expect

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type goalExpectFixture struct {
	testDir     string
	testDataDir string
	testDirTmp  bool
	t           *testing.T
	testFilter  string
}

func (f *goalExpectFixture) initialize(t *testing.T) (err error) {
	f.t = t
	f.testDir = os.Getenv("TESTDIR")
	if f.testDir == "" {
		f.testDir, _ = ioutil.TempDir("", "tmp")
		f.testDir = filepath.Join(f.testDir, "expect")
		err = os.MkdirAll(f.testDir, 0755)
		if err != nil {
			f.t.Errorf("error creating test dir %s, with error %v", f.testDir, err)
			return
		}
		f.testDirTmp = true
	}
	f.testDataDir = os.Getenv("TESTDATADIR")
	if f.testDataDir == "" {
		f.testDataDir = os.ExpandEnv("${GOPATH}/src/github.com/algorand/go-algorand/test/testdata")
	}

	f.testFilter = os.Getenv("TESTFILTER")
	if f.testFilter == "" {
		f.testFilter = ".*"
	}
	return
}

func (f *goalExpectFixture) getTestDir(testName string) (workingDir, algoDir string, err error) {
	testName = strings.Replace(testName, ".exp", "", -1)
	workingDir = filepath.Join(f.testDir, testName)
	err = os.Mkdir(workingDir, 0755)
	if err != nil {
		f.t.Errorf("error creating test dir %s, with error %v", workingDir, err)
		return
	}
	algoDir = filepath.Join(workingDir, "algod")
	err = os.Mkdir(algoDir, 0755)
	if err != nil {
		f.t.Errorf("error creating algo dir %s, with error %v", algoDir, err)
		return
	}
	return
}

func (f *goalExpectFixture) removeTestDir(workingDir string) (err error) {
	err = os.RemoveAll(workingDir)
	if err != nil {
		f.t.Errorf("error removing test dir %s, with error %v", workingDir, err)
		return
	}
	return
}

// TestGoalWithExpect Process all expect script files with suffix Test.exp within the test/e2e-go/cli/goal/expect directory
func TestGoalWithExpect(t *testing.T) {
	var f goalExpectFixture
	var execCommand = exec.Command
	expectFiles := make(map[string]string) // map expect test to full file name.
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(info.Name(), "Test.exp") {
			expectFiles[info.Name()] = path
		}
		return nil
	})
	require.NoError(t, err)
	err = f.initialize(t)
	require.NoError(t, err)

	for testName := range expectFiles {
		if match, _ := regexp.MatchString(f.testFilter, testName); match {
			t.Run(testName, func(t *testing.T) {
				if runtime.GOOS == "darwin" &&
					(testName == "basicGoalTest.exp" || testName == "createWalletTest.exp" || testName == "goalNodeStatusTest.exp") {
					t.Skip()
				}
				workingDir, algoDir, err := f.getTestDir(testName)
				require.NoError(t, err)
				t.Logf("algoDir: %s\ntestDataDir:%s\n", algoDir, f.testDataDir)
				cmd := execCommand("expect", testName, algoDir, f.testDataDir)
				var outBuf bytes.Buffer
				cmd.Stdout = &outBuf

				// Set stderr to be a file descriptor. In other way Go's exec.Cmd::writerDescriptor
				// attaches goroutine reading that blocks on io.Copy from stderr.
				// Cmd::CombinedOutput sets stderr to stdout and also blocks.
				// Cmd::Start + Cmd::Wait with manual pipes redirection etc also blocks.
				// Wrapping 'expect' with 'expect "$@" 2>&1' also blocks on stdout reading.
				// Cmd::Output with Cmd::Stderr == nil works but stderr get lost.
				// Using os.File as stderr does not trigger goroutine creation, instead exec.Cmd relies on os.File implementation.
				errFile, err := os.OpenFile(path.Join(workingDir, "stderr.txt"), os.O_CREATE|os.O_RDWR, 0)
				if err != nil {
					t.Logf("failed opening stderr temp file: %s\n", err.Error())
					t.Fail()
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
					t.Logf("err running '%s': %s\nstdout: %s\nstderr: %s\n", testName, err, string(outBuf.Bytes()), stderr)
					t.Fail()
				} else {
					// t.Logf("stdout: %s", string(outBuf.Bytes()))
					f.removeTestDir(workingDir)
				}
			})
		}
	}
}
