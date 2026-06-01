// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/config"
)

type baseFixture struct {
	Config config.Global

	binDir      string
	testDataDir string
	testDir     string
	testDirTmp  bool
	instance    Fixture
}

func getTestDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		return path.Join(path.Dir(filename), "..", "..")
	}
	// fallback to the legacy GOPATH location.
	return os.ExpandEnv("${GOPATH}/src/github.com/algorand/go-algorand/test/")
}

// goInstallBinDir reports where `go install` (and thus `make install`) places
// binaries, asking `go env` rather than trusting an exported $GOPATH. This
// mirrors the GOBIN/GOPATH resolution in the Makefile so a plain `go test`
// finds algod without requiring NODEBINDIR or an exported GOPATH.
func goInstallBinDir() string {
	if out, err := exec.Command("go", "env", "GOBIN").Output(); err == nil {
		if dir := strings.TrimSpace(string(out)); dir != "" {
			return dir
		}
	}
	out, err := exec.Command("go", "env", "GOPATH").Output()
	if err != nil {
		return ""
	}
	// GOPATH may be a list; go install uses the first entry.
	gopath := filepath.SplitList(strings.TrimSpace(string(out)))
	if len(gopath) == 0 || gopath[0] == "" {
		return ""
	}
	return filepath.Join(gopath[0], "bin")
}

func (f *baseFixture) initialize(instance Fixture) {
	f.instance = instance
	f.Config = config.Protocol
	f.binDir = os.Getenv("NODEBINDIR")
	if f.binDir == "" {
		f.binDir = goInstallBinDir()
	}
	f.testDir = os.Getenv("TESTDIR")
	if f.testDir == "" {
		f.testDir, _ = os.MkdirTemp("", "tmp")
		f.testDirTmp = true
	}
	f.testDataDir = os.Getenv("TESTDATADIR")
	if f.testDataDir == "" {
		f.testDataDir = path.Join(getTestDir(), "testdata")
	}
}

func (f *baseFixture) run(m *testing.M) int {
	return m.Run()
}

func (f *baseFixture) runAndExit(m *testing.M) {
	ret := m.Run()
	preserveData := ret != 0 // If ret != 0, something failed so preserve data
	f.instance.ShutdownImpl(preserveData)
	os.Exit(ret)
}

func (f *baseFixture) failOnError(err error, message string) {
	if err != nil {
		panic(fmt.Sprintf(message, err))
	}
}
