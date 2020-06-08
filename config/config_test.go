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

package config

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/codecs"
)

var defaultConfig = Local{
	Archival:     false,
	GossipFanout: 4,

	IncomingConnectionsLimit: -1, // -1 marks no limit, otherwise marks limit
	BaseLoggerDebugLevel:     1,  //Info level
}

func TestSaveThenLoad(t *testing.T) {
	c1, err := loadWithoutDefaults(defaultConfig)
	require.NoError(t, err)
	c1, err = migrate(c1)
	require.NoError(t, err)
	var b1 bytes.Buffer
	ser1 := json.NewEncoder(&b1)
	ser1.Encode(c1)

	os.RemoveAll("testdir")
	err = os.Mkdir("testdir", 0777)
	require.NoError(t, err)

	c1.SaveToDisk("testdir")

	c2, err := LoadConfigFromDisk("testdir")
	require.NoError(t, err)

	var b2 bytes.Buffer
	ser2 := json.NewEncoder(&b2)
	ser2.Encode(c2)

	require.True(t, bytes.Equal(b1.Bytes(), b2.Bytes()))

	os.RemoveAll("testdir")
}

func TestLoadMissing(t *testing.T) {
	os.RemoveAll("testdir")
	_, err := LoadConfigFromDisk("testdir")
	require.True(t, os.IsNotExist(err))
}

func TestMergeConfig(t *testing.T) {
	os.RemoveAll("testdir")
	err := os.Mkdir("testdir", 0777)

	c1 := struct {
		GossipFanout              int
		MaxNumberOfTxnsPerAccount int
		NetAddress                string
		ShouldNotExist            int // Ensure we don't panic when config has members we've removed
	}{}
	testInt := int(123)
	testString := "testing123"
	c1.GossipFanout = testInt
	c1.MaxNumberOfTxnsPerAccount = testInt
	c1.NetAddress = testString

	// write our reduced version of the Local struct
	fileToMerge := filepath.Join("testdir", ConfigFilename)
	f, err := os.OpenFile(fileToMerge, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		enc := json.NewEncoder(f)
		err = enc.Encode(c1)
		f.Close()
	}

	require.NoError(t, err)

	// Take defaultConfig and merge with the saved custom settings.
	// This should result in c2 being the same as defaultConfig except for the value(s) in our custom c1
	c2, err := mergeConfigFromDir("testdir", defaultConfig)

	require.NoError(t, err)
	require.Equal(t, defaultConfig.Archival || c1.NetAddress != "", c2.Archival)
	require.Equal(t, defaultConfig.IncomingConnectionsLimit, c2.IncomingConnectionsLimit)
	require.Equal(t, defaultConfig.BaseLoggerDebugLevel, c2.BaseLoggerDebugLevel)

	require.Equal(t, c1.NetAddress, c2.NetAddress)
	require.Equal(t, c1.GossipFanout, c2.GossipFanout)

	os.RemoveAll("testdir")
}

func saveFullPhonebook(phonebook phonebookBlackWhiteList) error {
	filename := filepath.Join("testdir", PhonebookFilename)
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		defer f.Close()
		enc := json.NewEncoder(f)
		err = enc.Encode(phonebook)
	}
	return err
}

var phonebook = phonebookBlackWhiteList{
	Include: []string{"Test1", "test2", "TEST3"},
}

var phonebookToMerge = phonebookBlackWhiteList{
	Include: []string{"test1", "addThisOne"},
}

var expectedMerged = []string{
	"test1", "test2", "addThisOne",
}

func TestLoadPhonebook(t *testing.T) {
	os.RemoveAll("testdir")
	err := os.Mkdir("testdir", 0777)
	require.NoError(t, err)

	err = saveFullPhonebook(phonebook)
	require.NoError(t, err)

	phonebookEntries, err := LoadPhonebook("testdir")
	require.NoError(t, err)
	require.Equal(t, 3, len(phonebookEntries))
	for index, entry := range phonebookEntries {
		require.Equal(t, phonebook.Include[index], entry)
	}
	os.RemoveAll("testdir")
}

func TestLoadPhonebookMissing(t *testing.T) {
	os.RemoveAll("testdir")
	_, err := LoadPhonebook("testdir")
	require.True(t, os.IsNotExist(err))
}

func TestArchivalIfRelay(t *testing.T) {
	testArchivalIfRelay(t, true)
}

func TestArchivalIfNotRelay(t *testing.T) {
	testArchivalIfRelay(t, false)
}

func testArchivalIfRelay(t *testing.T, relay bool) {
	os.RemoveAll("testdir")
	err := os.Mkdir("testdir", 0777)

	c1 := struct {
		NetAddress string
	}{}
	if relay {
		c1.NetAddress = ":1234"
	}

	// write our reduced version of the Local struct
	fileToMerge := filepath.Join("testdir", ConfigFilename)
	f, err := os.OpenFile(fileToMerge, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		enc := json.NewEncoder(f)
		err = enc.Encode(c1)
		f.Close()
	}
	require.NoError(t, err)
	require.False(t, defaultConfig.Archival, "Default should be non-archival")

	c2, err := mergeConfigFromDir("testdir", defaultConfig)
	require.NoError(t, err)
	if relay {
		require.True(t, c2.Archival, "Relay should be archival")
	} else {
		require.False(t, c2.Archival, "Non-relay should still be non-archival")
	}

	os.RemoveAll("testdir")
}

func TestConfigExampleIsCorrect(t *testing.T) {
	a := require.New(t)

	ourPath, err := os.Getwd()
	a.NoError(err)
	examplePath := filepath.Join(ourPath, "../installer/config.json.example")

	f, err := os.Open(examplePath)
	a.NoError(err)
	defer f.Close()

	dec := json.NewDecoder(f)
	var example Local
	err = dec.Decode(&example)
	a.NoError(err)
	a.Equal(example, defaultLocal)
}

// Returns the specified config prepared by
// serializing it (without default values) and
// unmarshaling it into a copy of defaultLocal.
// This mimics the behavior of saving an older config
// version (before new parameters exist), so we don't
// see their default (zero) values and instead see the
// new default because they won't exist in the old file.
func loadWithoutDefaults(cfg Local) (Local, error) {
	file, err := ioutil.TempFile("", "lwd")
	if err != nil {
		return Local{}, err
	}
	name := file.Name()
	file.Close()
	defer os.Remove(name)
	err = cfg.SaveToFile(name)
	if err != nil {
		return Local{}, err
	}
	cfg, err = loadConfigFromFile(name)
	return cfg, err
}

func TestConfigMigrate(t *testing.T) {
	t.Skip()
	a := require.New(t)

	c0, err := loadWithoutDefaults(defaultLocalV0)
	a.NoError(err)
	c0, err = migrate(c0)
	a.NoError(err)
	cLatest, err := migrate(defaultLocal)
	a.NoError(err)

	a.Equal(defaultLocal, c0)
	a.Equal(defaultLocal, cLatest)

	cLatest.Version = configVersion + 1
	_, err = migrate(cLatest)
	a.Error(err)

	// Ensure we don't migrate values that aren't the default old version
	c0Modified := defaultLocalV0
	c0Modified.BaseLoggerDebugLevel = defaultLocalV0.BaseLoggerDebugLevel + 1
	c0Modified, err = migrate(c0Modified)
	a.NoError(err)
	a.NotEqual(defaultLocal, c0Modified)
}

func TestConfigMigrateFromDisk(t *testing.T) {
	a := require.New(t)

	ourPath, err := os.Getwd()
	a.NoError(err)
	configsPath := filepath.Join(ourPath, "../test/testdata/configs")

	c0, err := loadConfigFromFile(filepath.Join(configsPath, "config-v0.json"))
	a.NoError(err)
	modified, err := migrate(c0)
	a.NoError(err)
	a.Equal(defaultLocal, modified)

	c1, err := loadConfigFromFile(filepath.Join(configsPath, "config-v1.json"))
	a.NoError(err)
	modified, err = migrate(c1)
	a.NoError(err)
	a.Equal(defaultLocal, modified)

	c2, err := loadConfigFromFile(filepath.Join(configsPath, "config-v2.json"))
	a.NoError(err)
	modified, err = migrate(c2)
	a.NoError(err)
	a.Equal(defaultLocal, modified)

	c3, err := loadConfigFromFile(filepath.Join(configsPath, "config-v3.json"))
	a.NoError(err)
	modified, err = migrate(c3)
	a.NoError(err)
	a.Equal(defaultLocal, modified)

	c4, err := loadConfigFromFile(filepath.Join(configsPath, "config-v4.json"))
	a.NoError(err)
	modified, err = migrate(c4)
	a.NoError(err)
	a.Equal(defaultLocal, modified)

	cNext := Local{Version: configVersion + 1}
	_, err = migrate(cNext)
	a.Error(err)
}

// Verify that nobody is changing the shipping default configurations
func TestConfigInvariant(t *testing.T) {
	a := require.New(t)

	a.Equal(uint32(8), configVersion, "If you bump Config Version, please update this test (and consider if you should be adding more)")

	ourPath, err := os.Getwd()
	a.NoError(err)
	configsPath := filepath.Join(ourPath, "../test/testdata/configs")

	c0 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v0.json"), &c0)
	a.NoError(err)
	a.Equal(defaultLocalV0, c0)

	c1 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v1.json"), &c1)
	a.NoError(err)
	a.Equal(defaultLocalV1, c1)

	c2 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v2.json"), &c2)
	a.NoError(err)
	a.Equal(defaultLocalV2, c2)

	c3 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v3.json"), &c3)
	a.NoError(err)
	a.Equal(defaultLocalV3, c3)

	c4 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v4.json"), &c4)
	a.NoError(err)
	a.Equal(defaultLocalV4, c4)

	c5 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v5.json"), &c5)
	a.NoError(err)
	a.Equal(defaultLocalV5, c5)

	c6 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v6.json"), &c6)
	a.NoError(err)
	a.Equal(defaultLocalV6, c6)

	c7 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v7.json"), &c7)
	a.NoError(err)
	a.Equal(defaultLocalV7, c7)

	c8 := Local{}
	err = codecs.LoadObjectFromFile(filepath.Join(configsPath, "config-v8.json"), &c8)
	a.NoError(err)
	a.Equal(defaultLocalV8, c8)
}

func TestConfigLatestVersion(t *testing.T) {
	a := require.New(t)

	// Make sure current version is correct for the assigned defaultLocal
	a.Equal(configVersion, defaultLocal.Version)
}

func TestConsensusUpgrades(t *testing.T) {
	a := require.New(t)

	// Starting with v7, ensure we have a path to ConsensusCurrentVersion
	currentVersionName := protocol.ConsensusV7
	latestVersionName := protocol.ConsensusCurrentVersion

	leadsTo := consensusUpgradesTo(a, currentVersionName, latestVersionName)
	a.True(leadsTo, "Consensus protocol must have upgrade path from %v to %v", currentVersionName, latestVersionName)
}

func consensusUpgradesTo(a *require.Assertions, currentName, targetName protocol.ConsensusVersion) bool {
	if currentName == targetName {
		return true
	}
	currentVersion, has := Consensus[currentName]
	a.True(has, "Consensus map should contain all references consensus versions: Missing '%v'", currentName)
	for upgrade := range currentVersion.ApprovedUpgrades {
		if upgrade == targetName {
			return true
		}
		return consensusUpgradesTo(a, upgrade, targetName)
	}
	return false
}

func TestConsensusLatestVersion(t *testing.T) {
	a := require.New(t)

	latest, has := Consensus[protocol.ConsensusCurrentVersion]
	a.True(has, "ConsensusCurrentVersion doesn't appear to be a known version: %v", protocol.ConsensusCurrentVersion)
	a.Empty(latest.ApprovedUpgrades, "Latest ConsensusVersion should not have any upgrades - update ConsensusCurrentVersion")
}

func TestLocal_DNSBootstrapArray(t *testing.T) {
	type fields struct {
		DNSBootstrapID string
	}
	type args struct {
		networkID protocol.NetworkID
	}
	tests := []struct {
		name               string
		fields             fields
		args               args
		wantBootstrapArray []string
	}{
		{name: "test1",
			fields:             fields{DNSBootstrapID: "<network>.cloudflare.com"},
			args:               args{networkID: "devnet"},
			wantBootstrapArray: []string{"devnet.cloudflare.com"},
		},
		{name: "test2",
			fields:             fields{DNSBootstrapID: "<network>.cloudflare.com;<network>.cloudfront.com"},
			args:               args{networkID: "devnet"},
			wantBootstrapArray: []string{"devnet.cloudflare.com", "devnet.cloudfront.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Local{
				DNSBootstrapID: tt.fields.DNSBootstrapID,
			}
			if gotBootstrapArray := cfg.DNSBootstrapArray(tt.args.networkID); !reflect.DeepEqual(gotBootstrapArray, tt.wantBootstrapArray) {
				t.Errorf("Local.DNSBootstrapArray() = %v, want %v", gotBootstrapArray, tt.wantBootstrapArray)
			}
		})
	}
}

func TestLocal_DNSBootstrap(t *testing.T) {
	type fields struct {
		DNSBootstrapID string
	}
	type args struct {
		network protocol.NetworkID
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{name: "test1",
			fields: fields{DNSBootstrapID: "<network>.cloudflare.com"},
			args:   args{network: "devnet"},
			want:   "devnet.cloudflare.com",
		},
		{name: "test2",
			fields: fields{DNSBootstrapID: "<network>.cloudflare.com;"},
			args:   args{network: "devnet"},
			want:   "devnet.cloudflare.com;",
		},
		{name: "test3",
			fields: fields{DNSBootstrapID: "<network>.cloudflare.com;<network>.cloudfront.com"},
			args:   args{network: "devnet"},
			want:   "devnet.cloudflare.com;devnet.cloudfront.com",
		},
		{name: "test4",
			fields: fields{DNSBootstrapID: "<network>.cloudflare.com;<network>.cloudfront.com;"},
			args:   args{network: "devnet"},
			want:   "devnet.cloudflare.com;devnet.cloudfront.com;",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Local{
				DNSBootstrapID: tt.fields.DNSBootstrapID,
			}
			if got := cfg.DNSBootstrap(tt.args.network); got != tt.want {
				t.Errorf("Local.DNSBootstrap() = %v, want %v", got, tt.want)
			}
		})
	}
}
