// Copyright (C) 2019 Algorand, Inc.
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
	a.Equal(elasticsearchEndpoint(), cfg.URI)
	a.NotZero(len(cfg.GUID))
	a.Equal(logrus.WarnLevel, cfg.MinLogLevel)
	a.Equal(logrus.WarnLevel, cfg.ReportHistoryLevel)
	a.Equal(uint(100), cfg.LogHistoryDepth)
}

func TestLoadDefaultConfig(t *testing.T) {
	a := require.New(t)

	configDir, err := ioutil.TempDir("", "testdir")
	currentRoot := config.SetGlobalConfigFileRoot(configDir)

	_, err = EnsureTelemetryConfig(nil, "")

	a.Nil(err)

	config.SetGlobalConfigFileRoot(currentRoot)
	os.RemoveAll(configDir)
}

func isDefault(cfg TelemetryConfig) bool {
	defaultCfg := createTelemetryConfig()
	cfg.FilePath = "" // Reset to compare the rest
	cfg.GUID = ""
	cfg.ChainID = ""
	defaultCfg.GUID = ""
	return cfg == defaultCfg
}

func TestEnsureErrorInvalidDirectory(t *testing.T) {
	a := require.New(t)

	cfgPath := "/missing-directory"
	cfg, err := EnsureTelemetryConfig(&cfgPath, "")

	a.True(os.IsNotExist(err)) // Should fail with FileNotExist making config, will fail when saved

	// Returned cfg should be same as default except
	// for the FilePath and GUID
	defaultCfg := createTelemetryConfig()
	a.Equal(cfg.FilePath, filepath.Join(cfgPath, loggingFilename))
	a.NotEqual(cfg.GUID, defaultCfg.GUID)

	a.True(isDefault(cfg))

	err = cfg.Save(cfg.FilePath)
	a.NotNil(err)
}

func TestSaveLoadConfig(t *testing.T) {
	a := require.New(t)

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
