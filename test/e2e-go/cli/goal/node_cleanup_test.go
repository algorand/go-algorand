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

package goal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestGoalNodeCleanup(t *testing.T) {
	defer fixture.SetTestContext(t)()
	a := require.New(fixtures.SynchronizedTest(t))

	primaryDir := fixture.PrimaryDataDir()
	nc := nodecontrol.MakeNodeController(fixture.GetBinDir(), primaryDir)
	_, err := nc.GetAlgodPID()
	a.NoErrorf(err, "Missing PID file for node directory %s", primaryDir)

	err = fixture.NodeStop()
	a.NoError(err, "Node stop failed")

	_, err = nc.GetAlgodPID()
	a.Errorf(err, "PID file present for node directory %s", primaryDir)

	err = fixture.NodeStart()
	a.NoError(err, "Node start failed")

	_, err = nc.GetAlgodPID()
	a.NoErrorf(err, "Missing PID file for node directory %s", primaryDir)
}
