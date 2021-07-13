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

package logging

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_loadTelemetryConfig(t *testing.T) {

	sample := TelemetryConfig{
		Enable:             true,
		GUID:               "guid",
		URI:                "elastic.algorand.com",
		MinLogLevel:        4,
		ReportHistoryLevel: 4,
		// These credentials are here intentionally. Not a bug.
		UserName: defaultTelemetryUsername,
		Password: defaultTelemetryPassword,
	}

	a := require.New(t)
	ourPath, err := os.Getwd()
	a.NoError(err)
	configsPath := filepath.Join(ourPath, "../test/testdata/configs/logging/logging.config.example")

	config, err := loadTelemetryConfig(configsPath)
	a.NoError(err)

	a.Equal(sample.Enable, config.Enable)
	a.Equal(sample.GUID, config.GUID)
	a.Equal(sample.URI, config.URI)
	a.Equal(sample.MinLogLevel, config.MinLogLevel)
	a.Equal(sample.ReportHistoryLevel, config.ReportHistoryLevel)
	a.Equal(sample.UserName, config.UserName)
	a.Equal(sample.Password, config.Password)

}

func Test_CreateSaveLoadTelemetryConfig(t *testing.T) {

	testDir := os.Getenv("TESTDIR")

	if testDir == "" {
		testDir, _ = ioutil.TempDir("", "tmp")
	}

	a := require.New(t)

	configsPath := filepath.Join(testDir, "logging.config")
	config1 := createTelemetryConfig()

	err := config1.Save(configsPath)
	a.NoError(err)

	config2, err := loadTelemetryConfig(configsPath)
	a.NoError(err)

	a.Equal(config1.Enable, config2.Enable)
	a.Equal(config1.URI, config2.URI)
	a.Equal(config1.Name, config2.Name)
	a.Equal(config1.GUID, config2.GUID)
	a.Equal(config1.MinLogLevel, config2.MinLogLevel)
	a.Equal(config1.ReportHistoryLevel, config2.ReportHistoryLevel)
	a.Equal(config1.FilePath, "")
	a.Equal(configsPath, config2.FilePath)
	a.Equal(config1.ChainID, config2.ChainID)
	a.Equal(config1.SessionGUID, config2.SessionGUID)
	a.Equal(config1.UserName, config2.UserName)
	a.Equal(config1.Password, config2.Password)

}

func Test_SanitizeTelemetryString(t *testing.T) {
	type testcase struct {
		input    string
		expected string
		parts    int
	}

	tests := []testcase{
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", 1},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1},
	}

	for _, test := range tests {
		require.Equal(t, test.expected, SanitizeTelemetryString(test.input, test.parts))
	}
}

func TestLoadTelemetryConfig(t *testing.T) {
	testLoggingConfigFileName := "../test/testdata/configs/logging/logging.config.test1"
	tc, err := loadTelemetryConfig(testLoggingConfigFileName)
	require.NoError(t, err)
	require.Equal(t, true, tc.Enable)
	// make sure the user name was loaded from the specified file
	require.Equal(t, "test-user-name", tc.UserName)
	// ensure we know how to default correctly if some of the fields in the configuration field aren't specified.
	require.Equal(t, createTelemetryConfig().Password, tc.Password)

}

func TestLoadTelemetryConfigBlankUsernamePassword(t *testing.T) {

	testLoggingConfigFileName := "../test/testdata/configs/logging/logging.config.test2"
	tc, err := loadTelemetryConfig(testLoggingConfigFileName)
	require.NoError(t, err)
	// make sure the user name was loaded from the specified file
	require.Equal(t, defaultTelemetryUsername, tc.UserName)
	// ensure we know how to default correctly if some of the fields in the configuration field aren't specified.
	require.Equal(t, defaultTelemetryPassword, tc.Password)
}

func TestSaveTelemetryConfigBlankUsernamePassword(t *testing.T) {

	testDir := os.Getenv("TESTDIR")

	if testDir == "" {
		testDir, _ = ioutil.TempDir("", "tmp")
	}

	a := require.New(t)

	configsPath := filepath.Join(testDir, "logging.config")

	config := createTelemetryConfig()

	// Ensure that config has default username and password
	config.UserName = defaultTelemetryUsername
	config.Password = defaultTelemetryPassword

	err := config.Save(configsPath)
	a.NoError(err)

	f, err := os.Open(configsPath)
	a.NoError(err)
	defer f.Close()

	var cfg TelemetryConfig

	var marshaledConfig MarshalingTelemetryConfig
	marshaledConfig.TelemetryConfig = createTelemetryConfig()

	dec := json.NewDecoder(f)
	err = dec.Decode(&marshaledConfig)
	a.NoError(err)

	cfg = marshaledConfig.TelemetryConfig
	a.Equal(cfg.UserName, "")
	a.Equal(cfg.Password, "")

}
