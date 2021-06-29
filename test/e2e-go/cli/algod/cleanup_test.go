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
	"github.com/algorand/go-algorand/testpartitioning"
)

func TestNodeControllerCleanup(t *testing.T) {
	testpartitioning.PartitionTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesPartialPartkeyOnlyWallets.json"))
	defer fixture.Shutdown()
	nodeDirs := fixture.NodeDataDirs()
	binDir := fixture.GetBinDir()

	// make sure that we have a pid file for each one of the nodes.
	for _, nodeDir := range nodeDirs {
		nc := nodecontrol.MakeNodeController(binDir, nodeDir)
		_, err := nc.GetAlgodPID()
		a.NoErrorf(err, "Missing PID file for node directory %s", nodeDir)
	}

	// stop each of the child processes.
	for _, nodeDir := range nodeDirs {
		nc := nodecontrol.MakeNodeController(binDir, nodeDir)
		err := nc.FullStop()
		a.NoErrorf(err, "Unable to stop node instance at %s", nodeDir)
	}

	// make sure that we dont have a pid file for each one of the nodes.
	for _, nodeDir := range nodeDirs {
		nc := nodecontrol.MakeNodeController(binDir, nodeDir)
		_, err := nc.GetAlgodPID()
		a.Errorf(err, "PID file present for node directory %s", nodeDir)
	}
}
