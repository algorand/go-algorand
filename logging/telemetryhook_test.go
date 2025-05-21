// Copyright (C) 2019-2025 Algorand, Inc.
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
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTelemetryConfig(t *testing.T) {
	partitiontest.PartitionTest(t)
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
	partitiontest.PartitionTest(t)
	a := require.New(t)

	currentRoot := config.SetGlobalConfigFileRoot(t.TempDir())
	defer config.SetGlobalConfigFileRoot(currentRoot)

	_, err := EnsureTelemetryConfig(nil, "")

	a.Nil(err)

}

func isDefault(cfg TelemetryConfig) bool {
	defaultCfg := createTelemetryConfig()
	cfg.FilePath = "" // Reset to compare the rest
	cfg.GUID = ""
	cfg.ChainID = ""
	cfg.Version = ""
	defaultCfg.GUID = ""
	return cfg == defaultCfg
}

func TestLoggingConfigDataDirFirst(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	globalConfigRoot := t.TempDir()
	oldConfigRoot := config.SetGlobalConfigFileRoot(globalConfigRoot)
	defer config.SetGlobalConfigFileRoot(oldConfigRoot)
	globalLoggingPath := filepath.Join(globalConfigRoot, TelemetryConfigFilename)

	dataDir := t.TempDir()
	dataDirLoggingPath := filepath.Join(dataDir, TelemetryConfigFilename)

	_, err := os.Stat(globalLoggingPath)
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
	a.NotEmpty(cfg.Version)

	// We got this from the tiny file we wrote to earlier.
	a.True(cfg.Enable)

	err = cfg.Save(cfg.FilePath)
	a.Nil(err)
}

func TestLoggingConfigGlobalSecond(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	globalConfigRoot := t.TempDir()
	oldConfigRoot := config.SetGlobalConfigFileRoot(globalConfigRoot)
	defer config.SetGlobalConfigFileRoot(oldConfigRoot)
	globalLoggingPath := filepath.Join(globalConfigRoot, TelemetryConfigFilename)

	_, err := os.Stat(globalLoggingPath)
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
	a.NotEmpty(cfg.Version)

	a.True(isDefault(cfg))

	err = cfg.Save(cfg.FilePath)
	a.Nil(err)
}

func TestSaveLoadConfig(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	globalConfigRoot := t.TempDir()
	oldConfigRoot := config.SetGlobalConfigFileRoot(globalConfigRoot)
	defer config.SetGlobalConfigFileRoot(oldConfigRoot)

	configDir := t.TempDir()
	err := os.Mkdir(configDir, 0777)

	cfg, err := EnsureTelemetryConfig(&configDir, "")
	cfg.Name = "testname"
	err = cfg.Save(cfg.FilePath)
	a.NoError(err)

	cfgLoad, err := LoadTelemetryConfig(cfg.FilePath)

	// ChainId and Version aren't stored.
	a.NotEmpty(cfg.ChainID)
	a.Empty(cfgLoad.ChainID)
	cfg.ChainID = ""

	a.NotEmpty(cfg.Version)
	a.Empty(cfgLoad.Version)
	cfg.Version = ""

	a.NoError(err)
	a.Equal("testname", cfgLoad.Name)
	a.Equal(cfgLoad, cfg)
}

func TestAsyncTelemetryHook_CloseDrop(t *testing.T) {
	partitiontest.PartitionTest(t)
	const entryCount = 100

	filling := make(chan struct{})

	testHook := makeMockTelemetryHook(logrus.DebugLevel)
	testHook.cb = func(entry *logrus.Entry) {
		<-filling // Block while filling
	}
	hook := createAsyncHook(&testHook, 4, entryCount)
	hook.ready = true
	for i := 0; i < entryCount; i++ {
		entry := logrus.Entry{
			Level: logrus.ErrorLevel,
		}
		hook.Fire(&entry)
	}

	close(filling)
	hook.Close()

	// To not block, we drop messages when they come in faster than the network sends them.
	require.Less(t, len(testHook.entries()), entryCount)
}

func TestAsyncTelemetryHook_QueueDepth(t *testing.T) {
	partitiontest.PartitionTest(t)
	const entryCount = 100
	const maxDepth = 10

	filling := make(chan struct{})

	testHook := makeMockTelemetryHook(logrus.DebugLevel)
	testHook.cb = func(entry *logrus.Entry) {
		<-filling // Block while filling
	}

	hook := createAsyncHook(&testHook, entryCount, maxDepth)
	hook.ready = true
	for i := 0; i < entryCount; i++ {
		entry := logrus.Entry{
			Level: logrus.ErrorLevel,
		}
		hook.Fire(&entry)
	}

	close(filling)
	hook.Close()

	hookEntries := len(testHook.entries())
	require.GreaterOrEqual(t, hookEntries, maxDepth)
	// the anonymous goroutine in createAsyncHookLevels might pull an entry off the pending list before
	// writing it off to the underlying hook. when that happens, the total number of sent entries could
	// be one higher then the maxDepth.
	require.LessOrEqual(t, hookEntries, maxDepth+1)
}

// Ensure that errors from inside the telemetryhook.go implementation are not reported to telemetry.
func TestAsyncTelemetryHook_SelfReporting(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const entryCount = 100
	const maxDepth = 10

	filling := make(chan struct{})

	testHook := makeMockTelemetryHook(logrus.DebugLevel)
	testHook.cb = func(entry *logrus.Entry) {
		<-filling // Block while filling
	}

	hook := createAsyncHook(&testHook, 100, 10)
	hook.ready = true
	for i := 0; i < entryCount; i++ {
		selfEntry := logrus.Entry{
			Level:   logrus.ErrorLevel,
			Data:    logrus.Fields{"TelemetryError": true},
			Message: "Unable to write event",
		}
		hook.Fire(&selfEntry)
	}
	close(filling)
	hook.Close()

	require.Len(t, testHook.entries(), 0)
}
