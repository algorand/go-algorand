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

package netdeploy

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/testpartitioning"
)

func TestSaveNetworkCfg(t *testing.T) {
	testpartitioning.PartitionTest(t)

	a := require.New(t)

	cfg := NetworkCfg{
		Name:         "testName",
		RelayDirs:    []string{"testPND"},
		TemplateFile: "testTemplate",
	}

	tmpFolder, _ := ioutil.TempDir("", "tmp")
	defer os.RemoveAll(tmpFolder)
	cfgFile := filepath.Join(tmpFolder, configFileName)
	err := saveNetworkCfg(cfg, cfgFile)
	a.Nil(err)
	cfg1, err := loadNetworkCfg(cfgFile)
	a.Equal(cfg, cfg1)
}

func TestSaveConsensus(t *testing.T) {
	testpartitioning.PartitionTest(t)

	a := require.New(t)

	tmpFolder, _ := ioutil.TempDir("", "tmp")
	defer os.RemoveAll(tmpFolder)
	relayDir := filepath.Join(tmpFolder, "testRelayDir")
	err := os.MkdirAll(relayDir, 0744)
	a.NoError(err)
	nodeDir := filepath.Join(tmpFolder, "testNodeDir")
	err = os.MkdirAll(nodeDir, 0744)
	a.NoError(err)

	net := Network{
		cfg: NetworkCfg{
			Name:         "testName",
			RelayDirs:    []string{relayDir},
			TemplateFile: "testTemplate",
		},
		nodeDirs: map[string]string{
			"node1": nodeDir,
		},
	}

	consensusRelayFilePath := filepath.Join(relayDir, config.ConfigurableConsensusProtocolsFilename)
	consensusNodeFilePath := filepath.Join(relayDir, config.ConfigurableConsensusProtocolsFilename)
	err = net.SetConsensus(tmpFolder, nil)
	a.NoError(err)
	_, err = os.Open(consensusRelayFilePath)
	a.True(os.IsNotExist(err), "%s should not have been created", config.ConfigurableConsensusProtocolsFilename)
	_, err = os.Open(consensusNodeFilePath)
	a.True(os.IsNotExist(err), "%s should not have been created", config.ConfigurableConsensusProtocolsFilename)

	err = net.SetConsensus(tmpFolder, config.Consensus)
	a.NoError(err)
	f, err := os.Open(consensusRelayFilePath)
	a.False(os.IsNotExist(err), "%s should have been created", config.ConfigurableConsensusProtocolsFilename)
	f.Close()
	f, err = os.Open(consensusNodeFilePath)
	a.False(os.IsNotExist(err), "%s should have been created", config.ConfigurableConsensusProtocolsFilename)
	f.Close()

	// now that the file exists, try to see if another call to SetConsensus would delete it.
	err = net.SetConsensus(tmpFolder, nil)
	a.NoError(err)
	_, err = os.Open(consensusRelayFilePath)
	a.True(os.IsNotExist(err), "%s should have been deleted", config.ConfigurableConsensusProtocolsFilename)
	_, err = os.Open(consensusNodeFilePath)
	a.True(os.IsNotExist(err), "%s should have been deleted", config.ConfigurableConsensusProtocolsFilename)
}
