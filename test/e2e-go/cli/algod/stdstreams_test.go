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

package algod

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/testPartitioning"
	"github.com/algorand/go-algorand/util"
)

func TestAlgodLogsToFile(t *testing.T) {
	testPartitioning.PartitionTest(t)

	t.Parallel()

	var fixture fixtures.LibGoalFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()
	binDir := fixture.GetBinDir()

	// Start one node with Redirect enabled and one without.
	// The one with redirect should not generate the algod-*.log files
	nc1 := nodecontrol.MakeNodeController(binDir, fixture.PrimaryDataDir())
	nc2 := nodecontrol.MakeNodeController(binDir, fixture.NodeDataDirs()[0])
	testNodeCreatesLogFiles(t, nc1, true)
	testNodeCreatesLogFiles(t, nc2, false)
}

func testNodeCreatesLogFiles(t *testing.T, nc nodecontrol.NodeController, redirect bool) {
	a := require.New(fixtures.SynchronizedTest(t))

	stdOutFile := filepath.Join(nc.GetDataDir(), nodecontrol.StdOutFilename)
	exists := util.FileExists(stdOutFile)
	a.False(exists, "StdOut file should not exist before starting")

	stdErrFile := filepath.Join(nc.GetDataDir(), nodecontrol.StdErrFilename)
	exists = util.FileExists(stdErrFile)
	a.False(exists, "StdErr file should not exist before starting")

	startArgs := nodecontrol.AlgodStartArgs{
		RedirectOutput: redirect,
	}
	nc.StartAlgod(startArgs)

	shouldWriteOutFiles := !redirect
	var failMessage string
	if shouldWriteOutFiles {
		failMessage = "file doesn't exist when it should"
	} else {
		failMessage = "file exists when it shouldn't"
	}
	a.Equal(shouldWriteOutFiles, util.FileExists(stdOutFile), "StdOut %s", failMessage)
	a.Equal(shouldWriteOutFiles, util.FileExists(stdErrFile), "StdErr %s", failMessage)
}
