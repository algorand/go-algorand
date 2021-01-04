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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
)

func TestTelemetryConfig(t *testing.T) {
	a := require.New(t)

	cfg := createTelemetryConfig()
	expectedEnabled := false
	a.Equal(expectedEnabled, cfg.Enable)
	a.Equal("", cfg.URI)
	a.NotZero(len(cfg.GUID))
	a.Equal(logrus.WarnLevel, cfg.MinLogLevel)
	a.Equal(logrus.WarnLevel, cfg.ReportHistoryLevel)
}

func TestLoadDefaultConfig(t *testing.T) {
	a := require.New(t)

	configDir, err := ioutil.TempDir("", "testdir")
	defer os.RemoveAll(configDir)
	currentRoot := config.SetGlobalConfigFileRoot(configDir)
	defer config.SetGlobalConfigFileRoot(currentRoot)

	_, err = EnsureTelemetryConfig(nil, "")

	a.Nil(err)

}

func isDefault(cfg TelemetryConfig) bool {
	defaultCfg := createTelemetryConfig()
	cfg.FilePath = "" // Reset to compare the rest
	cfg.GUID = ""
	cfg.ChainID = ""
	defaultCfg.GUID = ""
	return cfg == defaultCfg
}

func TestLoggingConfigDataDirFirst(t *testing.T) {
	a := require.New(t)

	globalConfigRoot, err := ioutil.TempDir("", "globalConfigRoot")
	defer os.RemoveAll(globalConfigRoot)
	oldConfigRoot := config.SetGlobalConfigFileRoot(globalConfigRoot)
	defer config.SetGlobalConfigFileRoot(oldConfigRoot)
	globalLoggingPath := filepath.Join(globalConfigRoot, TelemetryConfigFilename)

	dataDir, err := ioutil.TempDir("", "dataDir")
	defer os.RemoveAll(dataDir)
	dataDirLoggingPath := filepath.Join(dataDir, TelemetryConfigFilename)

	_, err = os.Stat(globalLoggingPath)
	a.True(os.IsNotExist(err))
	_, err = os.Stat(dataDirLoggingPath)
	a.True(os.IsNotExist(err))

	defaultCfg := createTelemetryConfig()
	a.False(defaultCfg.Enable) // if the default becomes true, flip the logic in this test to make it more interesting.

	fout, err := os.Create(dataDirLoggingPath)
	a.Nil(err)
	fout.Write([]byte("{\"Enable\":true}"))
	fout.Close()

	cfg, err := EnsureTelemetryConfig(&dataDir, "")
	a.Nil(err)

	_, err = os.Stat(globalLoggingPath)
	a.True(os.IsNotExist(err))
	_, err = os.Stat(dataDirLoggingPath)
	a.Nil(err)

	a.Equal(cfg.FilePath, dataDirLoggingPath)
	a.NotEqual(cfg.GUID, defaultCfg.GUID)

	// We got this from the tiny file we wrote to earlier.
	a.True(cfg.Enable)

	err = cfg.Save(cfg.FilePath)
	a.Nil(err)
}

func TestLoggingConfigGlobalSecond(t *testing.T) {
	a := require.New(t)

	globalConfigRoot, err := ioutil.TempDir("", "globalConfigRoot")
	defer os.RemoveAll(globalConfigRoot)
	oldConfigRoot := config.SetGlobalConfigFileRoot(globalConfigRoot)
	defer config.SetGlobalConfigFileRoot(oldConfigRoot)
	globalLoggingPath := filepath.Join(globalConfigRoot, TelemetryConfigFilename)

	_, err = os.Stat(globalLoggingPath)
	a.True(os.IsNotExist(err))

	cfgPath := "/missing-directory"
	cfg, err := EnsureTelemetryConfig(&cfgPath, "")

	a.Nil(err)
	_, err = os.Stat(globalLoggingPath)
	a.Nil(err)

	// Returned cfg should be same as default except
	// for the FilePath and GUID
	defaultCfg := createTelemetryConfig()
	a.Equal(cfg.FilePath, globalLoggingPath)
	a.NotEqual(cfg.GUID, defaultCfg.GUID)

	a.True(isDefault(cfg))

	err = cfg.Save(cfg.FilePath)
	a.Nil(err)
}

func TestSaveLoadConfig(t *testing.T) {
	a := require.New(t)

	globalConfigRoot, err := ioutil.TempDir("", "globalConfigRoot")
	defer os.RemoveAll(globalConfigRoot)
	oldConfigRoot := config.SetGlobalConfigFileRoot(globalConfigRoot)
	defer config.SetGlobalConfigFileRoot(oldConfigRoot)

	configDir, err := ioutil.TempDir("", "testdir")
	os.RemoveAll(configDir)
	err = os.Mkdir(configDir, 0777)

	cfg, err := EnsureTelemetryConfig(&configDir, "")
	cfg.Name = "testname"
	err = cfg.Save(cfg.FilePath)
	a.NoError(err)

	cfgLoad, err := LoadTelemetryConfig(cfg.FilePath)

	// ChainId isn't stored.
	a.NotEmpty(cfg.ChainID)
	a.Empty(cfgLoad.ChainID)
	cfg.ChainID = ""

	a.NoError(err)
	a.Equal("testname", cfgLoad.Name)
	a.Equal(cfgLoad, cfg)

	os.RemoveAll(configDir)
}

func TestAsyncTelemetryHook_Close(t *testing.T) {
	t.Skip("We no longer ensure 100% delivery. To not block, we drop messages when they come in faster than the network sends them.")
	a := require.New(t)
	t.Parallel()

	const entryCount = 100

	testHook := makeMockTelemetryHook(logrus.DebugLevel)
	testHook.cb = func(entry *logrus.Entry) {
		// Inject a delay to ensure we buffer entries
		time.Sleep(1 * time.Millisecond)
	}
	hook := createAsyncHook(&testHook, 4, entryCount)
	for i := 0; i < entryCount; i++ {
		entry := logrus.Entry{
			Level: logrus.ErrorLevel,
		}
		hook.Fire(&entry)
	}

	hook.Close()

	a.Equal(entryCount, len(testHook.entries()))
}

func TestAsyncTelemetryHook_QueueDepth(t *testing.T) {
	t.Skip("flakey test can fail on slow test systems")
	a := require.New(t)
	t.Parallel()

	const entryCount = 100
	const maxDepth = 10

	filling := make(chan struct{})

	testHook := makeMockTelemetryHook(logrus.DebugLevel)
	testHook.cb = func(entry *logrus.Entry) {
		<-filling // Block while filling
	}

	hook := createAsyncHook(&testHook, entryCount, maxDepth)
	for i := 0; i < entryCount; i++ {
		entry := logrus.Entry{
			Level: logrus.ErrorLevel,
		}
		hook.Fire(&entry)
	}

	close(filling)
	hook.Close()

	a.Equal(maxDepth, len(testHook.entries()))
}
