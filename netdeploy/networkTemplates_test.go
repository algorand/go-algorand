// Copyright (C) 2019-2023 Algorand, Inc.
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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLoadConfig(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	templateDir, err := filepath.Abs("../test/testdata/nettemplates")
	a.NoError(err)

	template, err := loadTemplate(filepath.Join(templateDir, "David20.json"))
	a.NoError(err)
	a.Equal(template.Genesis.NetworkName, "tbd")
}

func TestLoadMissingConfig(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	templateDir, err := filepath.Abs("../test/testdata/nettemplates")
	template, err := loadTemplate(filepath.Join(templateDir, "<invalidname>.json"))
	a.Error(err)
	a.Equal(template.Genesis.NetworkName, "")
}

func TestGenerateGenesis(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	templateDir, _ := filepath.Abs("../test/testdata/nettemplates")
	template, _ := loadTemplate(filepath.Join(templateDir, "David20.json"))

	targetFolder := t.TempDir()
	networkName := "testGenGen"
	binDir := os.ExpandEnv("${GOPATH}/bin")

	err := template.generateGenesisAndWallets(targetFolder, networkName, binDir)
	a.NoError(err)
	_, err = os.Stat(filepath.Join(targetFolder, config.GenesisJSONFile))
	fileExists := err == nil
	a.True(fileExists)
}

func TestValidate(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	templateDir, _ := filepath.Abs("../test/testdata/nettemplates")
	template, _ := loadTemplate(filepath.Join(templateDir, "David20.json"))
	err := template.Validate()
	a.NoError(err)

	templateDir, _ = filepath.Abs("../test/testdata/nettemplates")
	template, _ = loadTemplate(filepath.Join(templateDir, "TenThousandAccountsEqual.json"))
	err = template.Validate()
	a.NoError(err)

	templateDir, _ = filepath.Abs("../test/testdata/nettemplates")
	template, _ = loadTemplate(filepath.Join(templateDir, "NegativeStake.json"))
	err = template.Validate()
	a.Error(err)

	templateDir, _ = filepath.Abs("../test/testdata/nettemplates")
	template, _ = loadTemplate(filepath.Join(templateDir, "TwoNodesOneRelay1000Accounts.json"))
	err = template.Validate()
	a.NoError(err)
}

type overlayTestStruct struct {
	A string
	B string
}

// TestJsonOverlay ensures that encoding/json will only clobber fields present in the json and leave other fields unchanged
func TestJsonOverlay(t *testing.T) {
	before := overlayTestStruct{A: "one", B: "two"}
	setB := "{\"B\":\"other\"}"
	dec := json.NewDecoder(strings.NewReader(setB))
	after := before
	err := dec.Decode(&after)
	a := require.New(t)
	a.NoError(err)
	a.Equal("one", after.A)
	a.Equal("other", after.B)
}
