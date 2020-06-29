// Copyright (C) 2019-2020 Algorand, Inc.
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

package teal

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestTealCompile(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "OneNodeFuture.json"))

	// Get primary node
	primaryNode, err := fixture.GetNodeController("Primary")
	a.NoError(err)

	fixture.Start()
	defer primaryNode.FullStop()

	// get lib goal client
	libGoalClient := fixture.LibGoalFixture.GetLibGoalClientFromNodeController(primaryNode)

	compiledProgram, _, err := libGoalClient.Compile([]byte(""))
	a.Nil(compiledProgram)
	a.Equal(err.Error(), "HTTP 404 Not Found: /teal/compile was not enabled in the configuration file by setting the EnableDeveloperAPI to true")

	primaryNode.FullStop()

	// update the configuration file to enable the developer API
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.EnableDeveloperAPI = true
	cfg.SaveToDisk(primaryNode.GetDataDir())

	fixture.Start()

	var hash crypto.Digest
	compiledProgram, hash, err = libGoalClient.Compile([]byte("int 1"))
	a.NotNil(compiledProgram)
	a.NoError(err, "A valid program should result in a compilation success")
	a.Equal([]byte{0x41, 0x69, 0x41, 0x42, 0x41, 0x53, 0x49, 0x3d}, compiledProgram)
	a.Equal(crypto.Digest{0x59, 0x4f, 0x45, 0x36, 0x43, 0x32, 0x32, 0x47, 0x48, 0x43, 0x54, 0x4b, 0x41, 0x4e, 0x33, 0x48, 0x55, 0x34, 0x53, 0x45, 0x35, 0x50, 0x47, 0x49, 0x50, 0x4e, 0x35, 0x55, 0x4b, 0x58, 0x41, 0x4a}, hash)

	compiledProgram, _, err = libGoalClient.Compile([]byte("bad program"))
	a.Error(err, "A valid program should result in a compilation success")
	a.Nil(compiledProgram)
}
