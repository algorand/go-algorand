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

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/codecs"
)

var defaultConfig = Local{
	Archival:     false,
	GossipFanout: 4,

	IncomingConnectionsLimit: -1, // -1 marks no limit, otherwise marks limit
	BaseLoggerDebugLevel:     1,  //Info level
}

func TestLocal_SaveThenLoad(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	c1, err := loadWithoutDefaults(defaultConfig)
	require.NoError(t, err)
	c1, err = migrate(c1)
	require.NoError(t, err)
	var b1 bytes.Buffer
	ser1 := json.NewEncoder(&b1)
	ser1.Encode(c1)

	tempDir := t.TempDir()
	c1.SaveToDisk(tempDir)

	c2, err := LoadConfigFromDisk(tempDir)
	require.NoError(t, err)

	var b2 bytes.Buffer
	ser2 := json.NewEncoder(&b2)
	ser2.Encode(c2)

	require.True(t, bytes.Equal(b1.Bytes(), b2.Bytes()))
}

func TestConfig_LoadMissing(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tempDir := t.TempDir()
	os.RemoveAll(tempDir)
	_, err := LoadConfigFromDisk(tempDir)
	require.True(t, os.IsNotExist(err))
}

func TestLocal_MergeConfig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tempDir := t.TempDir()

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
	fileToMerge := filepath.Join(tempDir, ConfigFilename)
	f, err := os.OpenFile(fileToMerge, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		enc := json.NewEncoder(f)
		err = enc.Encode(c1)
		f.Close()
	}

	require.NoError(t, err)

	// Take defaultConfig and merge with the saved custom settings.
	// This should result in c2 being the same as defaultConfig except for the value(s) in our custom c1
	c2, err := mergeConfigFromDir(tempDir, defaultConfig)

	require.NoError(t, err)
	require.Equal(t, defaultConfig.Archival || c1.NetAddress != "", c2.Archival)
	require.Equal(t, defaultConfig.IncomingConnectionsLimit, c2.IncomingConnectionsLimit)
	require.Equal(t, defaultConfig.BaseLoggerDebugLevel, c2.BaseLoggerDebugLevel)

	require.Equal(t, c1.NetAddress, c2.NetAddress)
	require.Equal(t, c1.GossipFanout, c2.GossipFanout)
}

func saveFullPhonebook(phonebook phonebookBlackWhiteList, saveToDir string) error {
	filename := filepath.Join(saveToDir, PhonebookFilename)
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

func TestLoadPhonebook(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tempDir := t.TempDir()

	err := saveFullPhonebook(phonebook, tempDir)
	require.NoError(t, err)

	phonebookEntries, err := LoadPhonebook(tempDir)
	require.NoError(t, err)
	require.Equal(t, 3, len(phonebookEntries))
	for index, entry := range phonebookEntries {
		require.Equal(t, phonebook.Include[index], entry)
	}
}

func TestLoadPhonebookMissing(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tempDir := t.TempDir()
	_, err := LoadPhonebook(tempDir)
	require.True(t, os.IsNotExist(err))
}

func TestArchivalIfRelay(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testArchivalIfRelay(t, true)
}

func TestArchivalIfNotRelay(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testArchivalIfRelay(t, false)
}

func testArchivalIfRelay(t *testing.T, relay bool) {
	tempDir := t.TempDir()

	c1 := struct {
		NetAddress string
	}{}
	if relay {
		c1.NetAddress = ":1234"
	}

	// write our reduced version of the Local struct
	fileToMerge := filepath.Join(tempDir, ConfigFilename)
	f, err := os.OpenFile(fileToMerge, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		enc := json.NewEncoder(f)
		err = enc.Encode(c1)
		f.Close()
	}
	require.NoError(t, err)
	require.False(t, defaultConfig.Archival, "Default should be non-archival")

	c2, err := mergeConfigFromDir(tempDir, defaultConfig)
	require.NoError(t, err)
	if relay {
		require.True(t, c2.Archival, "Relay should be archival")
	} else {
		require.False(t, c2.Archival, "Non-relay should still be non-archival")
	}
}

func TestLocal_ConfigExampleIsCorrect(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	file, err := os.CreateTemp("", "lwd")
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

func TestLocal_ConfigMigrate(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	c0, err := loadWithoutDefaults(GetVersionedDefaultLocalConfig(0))
	a.NoError(err)
	c0, err = migrate(c0)
	a.NoError(err)
	cLatest, err := migrate(defaultLocal)
	a.NoError(err)

	a.Equal(defaultLocal, c0)
	a.Equal(defaultLocal, cLatest)

	cLatest.Version = getLatestConfigVersion() + 1
	_, err = migrate(cLatest)
	a.Error(err)

	// Ensure we don't migrate values that aren't the default old version
	c0Modified := GetVersionedDefaultLocalConfig(0)
	c0Modified.BaseLoggerDebugLevel = GetVersionedDefaultLocalConfig(0).BaseLoggerDebugLevel + 1
	c0Modified, err = migrate(c0Modified)
	a.NoError(err)
	a.NotEqual(defaultLocal, c0Modified)
}

func TestLocal_ConfigMigrateFromDisk(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ourPath, err := os.Getwd()
	a.NoError(err)
	configsPath := filepath.Join(ourPath, "../test/testdata/configs")

	for configVersion := uint32(0); configVersion <= getLatestConfigVersion(); configVersion++ {
		c, err := loadConfigFromFile(filepath.Join(configsPath, fmt.Sprintf("config-v%d.json", configVersion)))
		a.NoError(err)
		modified, err := migrate(c)
		a.NoError(err)
		a.Equal(defaultLocal, modified, "config-v%d.json", configVersion)
	}

	cNext := Local{Version: getLatestConfigVersion() + 1}
	_, err = migrate(cNext)
	a.Error(err)
}

// Verify that nobody is changing the shipping default configurations
func TestLocal_ConfigInvariant(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ourPath, err := os.Getwd()
	a.NoError(err)
	configsPath := filepath.Join(ourPath, "../test/testdata/configs")

	// for configVersion := uint32(0); configVersion <= getLatestConfigVersion(); configVersion++ {
	for configVersion := uint32(27); configVersion <= 27; configVersion++ {
		c := Local{}
		err = codecs.LoadObjectFromFile(filepath.Join(configsPath, fmt.Sprintf("config-v%d.json", configVersion)), &c)
		a.NoError(err)
		a.Equal(GetVersionedDefaultLocalConfig(configVersion), c)
	}
}

func TestLocal_ConfigLatestVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)

	// Make sure current version is correct for the assigned defaultLocal
	a.Equal(getLatestConfigVersion(), defaultLocal.Version)
}

func TestConsensusUpgrades(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	// Starting with v7, ensure we have a path to ConsensusCurrentVersion
	currentVersionName := protocol.ConsensusV7
	latestVersionName := protocol.ConsensusCurrentVersion

	leadsTo := consensusUpgradesTo(a, currentVersionName, latestVersionName, checkConsensusVersionName)
	a.True(leadsTo, "Consensus protocol must have upgrade path from %v to %v", currentVersionName, latestVersionName)
}

func checkConsensusVersionName(a *require.Assertions, name string) {
	// ensure versions come from official specs repo
	prefix1 := "https://github.com/algorandfoundation/specs/tree/"
	prefix2 := "https://github.com/algorand/spec/tree/"

	whitelist := map[string]bool{"v7": true, "v8": true, "v9": true, "v10": true, "v11": true, "v12": true}
	if !whitelist[name] {
		a.True(strings.HasPrefix(name, prefix1) || strings.HasPrefix(name, prefix2),
			"Consensus version %s does not start with allowed prefix", name)
	}
}

func consensusUpgradesTo(a *require.Assertions, currentName, targetName protocol.ConsensusVersion, nameCheckFn func(*require.Assertions, string)) bool {
	nameCheckFn(a, string(currentName))
	if currentName == targetName {
		return true
	}
	currentVersion, has := Consensus[currentName]
	a.True(has, "Consensus map should contain all references consensus versions: Missing '%v'", currentName)
	for upgrade := range currentVersion.ApprovedUpgrades {
		nameCheckFn(a, string(upgrade))
		if upgrade == targetName {
			return true
		}
		return consensusUpgradesTo(a, upgrade, targetName, nameCheckFn)
	}
	return false
}

func TestConsensusLatestVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	latest, has := Consensus[protocol.ConsensusCurrentVersion]
	a.True(has, "ConsensusCurrentVersion doesn't appear to be a known version: %v", protocol.ConsensusCurrentVersion)
	a.Empty(latest.ApprovedUpgrades, "Latest ConsensusVersion should not have any upgrades - update ConsensusCurrentVersion")
}

func TestLocal_DNSBootstrapArray(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
		wantBootstrapArray []*DNSBootstrap
	}{
		{name: "test1",
			fields:             fields{DNSBootstrapID: "<network>.cloudflare.com"},
			args:               args{networkID: "devnet"},
			wantBootstrapArray: []*DNSBootstrap{{PrimarySRVBootstrap: "devnet.cloudflare.com"}},
		},
		{name: "test2",
			fields:             fields{DNSBootstrapID: "<network>.cloudflare.com;<network>.cloudfront.com"},
			args:               args{networkID: "devnet"},
			wantBootstrapArray: []*DNSBootstrap{{PrimarySRVBootstrap: "devnet.cloudflare.com"}, {PrimarySRVBootstrap: "devnet.cloudfront.com"}},
		},
		{name: "test3",
			fields:             fields{DNSBootstrapID: ""},
			args:               args{networkID: "devnet"},
			wantBootstrapArray: []*DNSBootstrap(nil),
		},
		{name: "test4 - intended to mismatch local template",
			fields: fields{DNSBootstrapID: "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)"},
			args:   args{networkID: "testnet"},
			wantBootstrapArray: []*DNSBootstrap{{PrimarySRVBootstrap: "testnet.algorand.network",
				BackupSRVBootstrap: "testnet.algorand.net",
				DedupExp:           regexp.MustCompile("(algorand-testnet.(network|net))")}},
		},
		{name: "test5 - intended to match legacy template",
			fields:             fields{DNSBootstrapID: "<network>.algorand.network"},
			args:               args{networkID: "testnet"},
			wantBootstrapArray: []*DNSBootstrap{{PrimarySRVBootstrap: "testnet.algorand.network"}},
		},
		{name: "test6 - exercise record append with full template",
			fields: fields{DNSBootstrapID: "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net);<network>.cloudfront.com"},
			args:   args{networkID: "devnet"},
			wantBootstrapArray: []*DNSBootstrap{{PrimarySRVBootstrap: "devnet.algorand.network",
				BackupSRVBootstrap: "devnet.algorand.net",
				DedupExp:           regexp.MustCompile("(algorand-devnet.(network|net))")},
				{PrimarySRVBootstrap: "devnet.cloudfront.com"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Local{
				DNSBootstrapID: tt.fields.DNSBootstrapID,
			}
			if gotBootstrapArray := cfg.DNSBootstrapArray(tt.args.networkID); !reflect.DeepEqual(gotBootstrapArray, tt.wantBootstrapArray) {
				t.Errorf("Local.DNSBootstrapArray() = %#v, want %#v", gotBootstrapArray, tt.wantBootstrapArray)
			}
			// handling should be identical to DNSBootstrapArray method for all of these cases
			if gotBootstrapArray, _ := cfg.ValidateDNSBootstrapArray(tt.args.networkID); !reflect.DeepEqual(gotBootstrapArray, tt.wantBootstrapArray) {
				t.Errorf("Local.DNSBootstrapArray() = %#v, want %#v", gotBootstrapArray, tt.wantBootstrapArray)
			}
		})
	}
}

func TestLocal_ValidateDNSBootstrapArray_StopsOnError(t *testing.T) {
	partitiontest.PartitionTest(t)

	var dnsBootstrapIDWithInvalidNameMacroUsage = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.((network|net)"

	cfg := Local{
		DNSBootstrapID: dnsBootstrapIDWithInvalidNameMacroUsage,
	}

	_, err := cfg.ValidateDNSBootstrapArray(Mainnet)

	assert.ErrorContains(t, err, bootstrapDedupRegexDoesNotCompile)
}

func TestLocal_StructTags(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	localType := reflect.TypeOf(Local{})

	versionField, ok := localType.FieldByName("Version")
	require.True(t, ok)
	ver := 0
	versionTags := []string{}
	for {
		_, has := versionField.Tag.Lookup(fmt.Sprintf("version[%d]", ver))
		if !has {
			break
		}
		versionTags = append(versionTags, fmt.Sprintf("version[%d]", ver))
		ver++
	}

	for fieldNum := 0; fieldNum < localType.NumField(); fieldNum++ {
		field := localType.Field(fieldNum)
		if field.Tag == "" {
			require.Failf(t, "Field is missing versioning information", "Field Name: %s", field.Name)
		}
		// the field named "Version" is tested separately in TestLocalVersionField, so we'll be skipping
		// it on this test.
		if field.Name == "Version" {
			continue
		}
		// check to see if we have at least a single version from the versions tags above.
		foundTag := false
		expectedTag := ""
		for _, ver := range versionTags {
			if val, found := field.Tag.Lookup(ver); found {
				foundTag = true
				expectedTag = expectedTag + ver + ":\"" + val + "\" "
			}
		}
		require.True(t, foundTag)
		expectedTag = expectedTag[:len(expectedTag)-1]
		require.Equal(t, expectedTag, string(field.Tag))
	}
}

func TestLocal_GetVersionedDefaultLocalConfig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for i := uint32(0); i < getLatestConfigVersion(); i++ {
		localVersion := GetVersionedDefaultLocalConfig(i)
		require.Equal(t, uint32(i), localVersion.Version)
	}
}

// TestLocalVersionField - ensures the Version contains only versions tags, the versions are all contiguous, and that no non-version tags are included there.
func TestLocal_VersionField(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	localType := reflect.TypeOf(Local{})
	field, ok := localType.FieldByName("Version")
	require.True(t, true, ok)
	ver := 0
	expectedTag := ""
	for {
		val, has := field.Tag.Lookup(fmt.Sprintf("version[%d]", ver))
		if !has {
			break
		}
		expectedTag = fmt.Sprintf("%sversion[%d]:\"%s\" ", expectedTag, ver, val)
		ver++
	}
	expectedTag = expectedTag[:len(expectedTag)-1]
	require.Equal(t, expectedTag, string(field.Tag))
}

func TestLocal_GetNonDefaultConfigValues(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := GetDefaultLocal()

	// set 4 non-default values
	cfg.AgreementIncomingBundlesQueueLength = 2
	cfg.AgreementIncomingProposalsQueueLength = 200
	cfg.TxPoolSize = 30
	cfg.Archival = true

	// ask for 2 of them
	ndmap := GetNonDefaultConfigValues(cfg, []string{"AgreementIncomingBundlesQueueLength", "TxPoolSize"})

	// assert correct
	expected := map[string]interface{}{
		"AgreementIncomingBundlesQueueLength": uint64(2),
		"TxPoolSize":                          int(30),
	}
	assert.Equal(t, expected, ndmap)

	// ask for field that doesn't exist: should skip
	assert.Equal(t, expected, GetNonDefaultConfigValues(cfg, []string{"Blah", "AgreementIncomingBundlesQueueLength", "TxPoolSize"}))

	// check unmodified defaults
	assert.Empty(t, GetNonDefaultConfigValues(GetDefaultLocal(), []string{"AgreementIncomingBundlesQueueLength", "TxPoolSize"}))
}

func TestLocal_TxFiltering(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := GetDefaultLocal()

	// ensure the default
	require.True(t, cfg.TxFilterRawMsgEnabled())
	require.False(t, cfg.TxFilterCanonicalEnabled())

	cfg.TxIncomingFilteringFlags = 0
	require.False(t, cfg.TxFilterRawMsgEnabled())
	require.False(t, cfg.TxFilterCanonicalEnabled())

	cfg.TxIncomingFilteringFlags = 1
	require.True(t, cfg.TxFilterRawMsgEnabled())
	require.False(t, cfg.TxFilterCanonicalEnabled())

	cfg.TxIncomingFilteringFlags = 2
	require.False(t, cfg.TxFilterRawMsgEnabled())
	require.True(t, cfg.TxFilterCanonicalEnabled())

	cfg.TxIncomingFilteringFlags = 3
	require.True(t, cfg.TxFilterRawMsgEnabled())
	require.True(t, cfg.TxFilterCanonicalEnabled())
}

func TestLocal_IsGossipServer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := GetDefaultLocal()
	require.False(t, cfg.IsGossipServer())

	cfg.NetAddress = ":4160"
	require.True(t, cfg.IsGossipServer())
}

func TestLocal_RecalculateConnectionLimits(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var tests = []struct {
		maxFDs     uint64
		reservedIn uint64
		restSoftIn uint64
		restHardIn uint64
		incomingIn int

		updated     bool
		restSoftExp uint64
		restHardExp uint64
		incomingExp int
	}{
		{100, 10, 20, 40, 50, false, 20, 40, 50},               // no change
		{100, 10, 20, 50, 50, true, 20, 40, 50},                // borrow from rest
		{100, 10, 25, 50, 50, true, 25, 40, 50},                // borrow from rest
		{100, 10, 50, 50, 50, true, 40, 40, 50},                // borrow from rest, update soft
		{100, 10, 9, 19, 81, true, 9, 10, 80},                  // borrow from both rest and incoming
		{100, 10, 10, 20, 80, true, 10, 10, 80},                // borrow from both rest and incoming
		{100, 50, 10, 30, 40, true, 10, 10, 40},                // borrow from both rest and incoming
		{100, 90, 10, 30, 40, true, 10, 10, 0},                 // borrow from both rest and incoming, clear incoming
		{4096, 256, 1024, 2048, 2400, true, 1024, 1440, 2400},  // real numbers
		{5000, 256, 1024, 2048, 2400, false, 1024, 2048, 2400}, // real numbers
	}

	for i, test := range tests {
		test := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			c := Local{
				RestConnectionsSoftLimit: test.restSoftIn,
				RestConnectionsHardLimit: test.restHardIn,
				IncomingConnectionsLimit: test.incomingIn,
			}
			requireFDs := test.reservedIn + test.restHardIn + uint64(test.incomingIn)
			res := c.AdjustConnectionLimits(requireFDs, test.maxFDs)
			require.Equal(t, test.updated, res)
			require.Equal(t, test.restSoftExp, c.RestConnectionsSoftLimit)
			require.Equal(t, test.restHardExp, c.RestConnectionsHardLimit)
			require.Equal(t, test.incomingExp, c.IncomingConnectionsLimit)
		})
	}
}

// Tests that ensureAbsGenesisDir resolves a path to an absolute path, appends the genesis directory, and creates any needed directories
func TestEnsureAbsDir(t *testing.T) {
	partitiontest.PartitionTest(t)

	testDirectory := t.TempDir()

	t1 := filepath.Join(testDirectory, "test1")
	t1Abs, err := ensureAbsGenesisDir(t1, "myGenesisID")
	require.NoError(t, err)
	require.DirExists(t, t1Abs)
	require.Equal(t, testDirectory+"/test1/myGenesisID", t1Abs)

	// confirm that relative paths become absolute
	t2 := filepath.Join(testDirectory, "test2", "..")
	t2Abs, err := ensureAbsGenesisDir(t2, "myGenesisID")
	require.NoError(t, err)
	require.DirExists(t, t2Abs)
	require.Equal(t, testDirectory+"/myGenesisID", t2Abs)
}

type tLogger struct{ t *testing.T }

func (l tLogger) Infof(fmts string, args ...interface{}) {
	l.t.Logf(fmts, args...)
}

// TestEnsureAndResolveGenesisDirs confirms that paths provided in the config are resolved to absolute paths and are created if relevant
func TestEnsureAndResolveGenesisDirs(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := GetDefaultLocal()

	testDirectory := t.TempDir()
	// insert some "Bad" path elements to see them removed when converted to absolute
	cfg.TrackerDBDir = filepath.Join(testDirectory, "BAD/../custom_tracker")
	cfg.BlockDBDir = filepath.Join(testDirectory, "/BAD/BAD/../../custom_block")
	cfg.CrashDBDir = filepath.Join(testDirectory, "custom_crash")
	cfg.StateproofDir = filepath.Join(testDirectory, "/RELATIVEPATHS/../RELATIVE/../custom_stateproof")
	cfg.CatchpointDir = filepath.Join(testDirectory, "custom_catchpoint")

	paths, err := cfg.EnsureAndResolveGenesisDirs(testDirectory, "myGenesisID", tLogger{t: t})
	require.NoError(t, err)

	// confirm that the paths are absolute, and contain the genesisID
	require.Equal(t, testDirectory+"/custom_tracker/myGenesisID", paths.TrackerGenesisDir)
	require.DirExists(t, paths.TrackerGenesisDir)
	require.Equal(t, testDirectory+"/custom_block/myGenesisID", paths.BlockGenesisDir)
	require.DirExists(t, paths.BlockGenesisDir)
	require.Equal(t, testDirectory+"/custom_crash/myGenesisID", paths.CrashGenesisDir)
	require.DirExists(t, paths.CrashGenesisDir)
	require.Equal(t, testDirectory+"/custom_stateproof/myGenesisID", paths.StateproofGenesisDir)
	require.DirExists(t, paths.StateproofGenesisDir)
	require.Equal(t, testDirectory+"/custom_catchpoint/myGenesisID", paths.CatchpointGenesisDir)
	require.DirExists(t, paths.CatchpointGenesisDir)
}

// TestEnsureAndResolveGenesisDirs_hierarchy confirms that when only some directories are specified, other directories defer to them
func TestEnsureAndResolveGenesisDirs_hierarchy(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := GetDefaultLocal()
	testDirectory := t.TempDir()
	paths, err := cfg.EnsureAndResolveGenesisDirs(testDirectory, "myGenesisID", tLogger{t: t})
	require.NoError(t, err)
	// confirm that if only the root is specified, it is used for all directories
	require.Equal(t, testDirectory+"/myGenesisID", paths.TrackerGenesisDir)
	require.DirExists(t, paths.TrackerGenesisDir)
	require.Equal(t, testDirectory+"/myGenesisID", paths.BlockGenesisDir)
	require.DirExists(t, paths.BlockGenesisDir)
	require.Equal(t, testDirectory+"/myGenesisID", paths.CrashGenesisDir)
	require.DirExists(t, paths.CrashGenesisDir)
	require.Equal(t, testDirectory+"/myGenesisID", paths.StateproofGenesisDir)
	require.DirExists(t, paths.StateproofGenesisDir)
	require.Equal(t, testDirectory+"/myGenesisID", paths.CatchpointGenesisDir)
	require.DirExists(t, paths.CatchpointGenesisDir)

	cfg = GetDefaultLocal()
	testDirectory = t.TempDir()
	hot := filepath.Join(testDirectory, "hot")
	cold := filepath.Join(testDirectory, "cold")
	cfg.HotDataDir = hot
	cfg.ColdDataDir = cold
	paths, err = cfg.EnsureAndResolveGenesisDirs(testDirectory, "myGenesisID", tLogger{t: t})
	require.NoError(t, err)
	// confirm that if hot/cold are specified, hot/cold are used for appropriate directories
	require.Equal(t, hot+"/myGenesisID", paths.TrackerGenesisDir)
	require.DirExists(t, paths.TrackerGenesisDir)
	require.Equal(t, cold+"/myGenesisID", paths.BlockGenesisDir)
	require.DirExists(t, paths.BlockGenesisDir)
	require.Equal(t, hot+"/myGenesisID", paths.CrashGenesisDir)
	require.DirExists(t, paths.CrashGenesisDir)
	require.Equal(t, hot+"/myGenesisID", paths.StateproofGenesisDir)
	require.DirExists(t, paths.StateproofGenesisDir)
	require.Equal(t, cold+"/myGenesisID", paths.CatchpointGenesisDir)
	require.DirExists(t, paths.CatchpointGenesisDir)
}

func TestEnsureAndResolveGenesisDirs_migrate(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := GetDefaultLocal()
	testDirectory := t.TempDir()
	cfg.HotDataDir = filepath.Join(testDirectory, "hot")
	cfg.ColdDataDir = filepath.Join(testDirectory, "cold")
	coldDir := filepath.Join(cfg.ColdDataDir, "myGenesisID")
	hotDir := filepath.Join(cfg.HotDataDir, "myGenesisID")
	err := os.MkdirAll(coldDir, 0755)
	require.NoError(t, err)
	// put a crash.sqlite file in the ColdDataDir
	err = os.WriteFile(filepath.Join(coldDir, "crash.sqlite"), []byte("test"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(coldDir, "crash.sqlite-shm"), []byte("test"), 0644)
	require.NoError(t, err)
	// put a stateproof.sqlite file in the ColdDataDir
	err = os.WriteFile(filepath.Join(coldDir, "stateproof.sqlite"), []byte("test"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(coldDir, "stateproof.sqlite-wal"), []byte("test"), 0644)
	require.NoError(t, err)
	// Resolve
	paths, err := cfg.EnsureAndResolveGenesisDirs(testDirectory, "myGenesisID", tLogger{t: t})
	require.NoError(t, err)
	// Confirm that crash.sqlite was moved to HotDataDir
	require.DirExists(t, paths.CrashGenesisDir)
	require.Equal(t, hotDir, paths.CrashGenesisDir)
	require.NoFileExists(t, filepath.Join(coldDir, "crash.sqlite"))
	require.NoFileExists(t, filepath.Join(coldDir, "crash.sqlite-shm"))
	require.FileExists(t, filepath.Join(hotDir, "crash.sqlite"))
	require.FileExists(t, filepath.Join(hotDir, "crash.sqlite-shm"))
	// Confirm that stateproof.sqlite was moved to HotDataDir
	require.DirExists(t, paths.StateproofGenesisDir)
	require.Equal(t, hotDir, paths.StateproofGenesisDir)
	require.NoFileExists(t, filepath.Join(coldDir, "stateproof.sqlite"))
	require.NoFileExists(t, filepath.Join(coldDir, "stateproof.sqlite-wal"))
	require.FileExists(t, filepath.Join(hotDir, "stateproof.sqlite"))
	require.FileExists(t, filepath.Join(hotDir, "stateproof.sqlite-wal"))
}

func TestEnsureAndResolveGenesisDirs_migrateCrashFail(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := GetDefaultLocal()
	testDirectory := t.TempDir()
	cfg.HotDataDir = filepath.Join(testDirectory, "hot")
	cfg.ColdDataDir = filepath.Join(testDirectory, "cold")
	coldDir := filepath.Join(cfg.ColdDataDir, "myGenesisID")
	hotDir := filepath.Join(cfg.HotDataDir, "myGenesisID")
	err := os.MkdirAll(coldDir, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(hotDir, 0755)
	require.NoError(t, err)
	// put a crash.sqlite file in the ColdDataDir
	err = os.WriteFile(filepath.Join(coldDir, "crash.sqlite"), []byte("test"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(coldDir, "crash.sqlite-shm"), []byte("test"), 0644)
	require.NoError(t, err)
	// also put a crash.sqlite file in the HotDataDir
	err = os.WriteFile(filepath.Join(hotDir, "crash.sqlite"), []byte("test"), 0644)
	require.NoError(t, err)
	// Resolve
	paths, err := cfg.EnsureAndResolveGenesisDirs(testDirectory, "myGenesisID", tLogger{t: t})
	require.Error(t, err)
	require.Empty(t, paths)
	// Confirm that crash.sqlite was not moved to HotDataDir
	require.FileExists(t, filepath.Join(coldDir, "crash.sqlite"))
	require.FileExists(t, filepath.Join(coldDir, "crash.sqlite-shm"))
	require.FileExists(t, filepath.Join(hotDir, "crash.sqlite"))
	require.NoFileExists(t, filepath.Join(hotDir, "crash.sqlite-shm"))
}

func TestEnsureAndResolveGenesisDirs_migrateSPFail(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := GetDefaultLocal()
	testDirectory := t.TempDir()
	cfg.HotDataDir = filepath.Join(testDirectory, "hot")
	cfg.ColdDataDir = filepath.Join(testDirectory, "cold")
	coldDir := filepath.Join(cfg.ColdDataDir, "myGenesisID")
	hotDir := filepath.Join(cfg.HotDataDir, "myGenesisID")
	err := os.MkdirAll(coldDir, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(hotDir, 0755)
	require.NoError(t, err)
	// put a stateproof.sqlite file in the ColdDataDir
	err = os.WriteFile(filepath.Join(coldDir, "stateproof.sqlite"), []byte("test"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(coldDir, "stateproof.sqlite-wal"), []byte("test"), 0644)
	require.NoError(t, err)
	// also put a stateproof.sqlite-wal file in the HotDataDir
	err = os.WriteFile(filepath.Join(hotDir, "stateproof.sqlite-wal"), []byte("test"), 0644)
	require.NoError(t, err)
	// Resolve
	paths, err := cfg.EnsureAndResolveGenesisDirs(testDirectory, "myGenesisID", tLogger{t: t})
	require.Error(t, err)
	require.Empty(t, paths)
	// Confirm that stateproof.sqlite was not moved to HotDataDir
	require.FileExists(t, filepath.Join(coldDir, "stateproof.sqlite"))
	require.FileExists(t, filepath.Join(coldDir, "stateproof.sqlite-wal"))
	require.NoFileExists(t, filepath.Join(hotDir, "stateproof.sqlite"))
	require.FileExists(t, filepath.Join(hotDir, "stateproof.sqlite-wal"))
}

// TestEnsureAndResolveGenesisDirsError confirms that if a path can't be created, an error is returned
func TestEnsureAndResolveGenesisDirsError(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := GetDefaultLocal()

	testDirectory := t.TempDir()
	// insert some "Bad" path elements to see them removed when converted to absolute
	cfg.TrackerDBDir = filepath.Join(testDirectory, "BAD/../custom_tracker")
	cfg.BlockDBDir = filepath.Join(testDirectory, "/BAD/BAD/../../custom_block")
	cfg.CrashDBDir = filepath.Join(testDirectory, "custom_crash")
	cfg.StateproofDir = filepath.Join(testDirectory, "/RELATIVEPATHS/../RELATIVE/../custom_stateproof")
	cfg.CatchpointDir = filepath.Join(testDirectory, "custom_catchpoint")

	// first try an error with an empty root dir
	paths, err := cfg.EnsureAndResolveGenesisDirs("", "myGenesisID", tLogger{t: t})
	require.Empty(t, paths)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rootDir is required")

	require.NoError(t, os.Chmod(testDirectory, 0200))

	// now try an error with a root dir that can't be written to
	paths, err = cfg.EnsureAndResolveGenesisDirs(testDirectory, "myGenesisID", tLogger{t: t})
	require.Empty(t, paths)
	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
}

// TestResolveLogPaths confirms that log paths are resolved to the most appropriate data directory of the supplied config
func TestResolveLogPaths(t *testing.T) {
	partitiontest.PartitionTest(t)

	// on default settings, the log paths should be in the root directory
	cfg := GetDefaultLocal()
	log, archive := cfg.ResolveLogPaths("root")
	require.Equal(t, "root/node.log", log)
	require.Equal(t, "root/node.archive.log", archive)

	// with supplied hot/cold data directories, they resolve to hot/cold
	cfg = GetDefaultLocal()
	cfg.HotDataDir = "hot"
	cfg.ColdDataDir = "cold"
	log, archive = cfg.ResolveLogPaths("root")
	require.Equal(t, "hot/node.log", log)
	require.Equal(t, "cold/node.archive.log", archive)

	// with supplied hot/cold data AND specific paths directories, they resolve to the specific paths
	cfg = GetDefaultLocal()
	cfg.HotDataDir = "hot"
	cfg.ColdDataDir = "cold"
	cfg.LogFileDir = "mycoolLogDir"
	cfg.LogArchiveDir = "myCoolLogArchive"
	log, archive = cfg.ResolveLogPaths("root")
	require.Equal(t, "mycoolLogDir/node.log", log)
	require.Equal(t, "myCoolLogArchive/node.archive.log", archive)
}

func TestStoresCatchpoints(t *testing.T) {
	partitiontest.PartitionTest(t)

	var tests = []struct {
		name               string
		catchpointTracking int64
		catchpointInterval uint64
		archival           bool
		expected           bool
	}{
		{
			name:               "-1 w/ no catchpoint interval expects false",
			catchpointTracking: CatchpointTrackingModeUntracked,
			catchpointInterval: 0,
			expected:           false,
		},
		{
			name:               "-1 expects false",
			catchpointTracking: CatchpointTrackingModeUntracked,
			catchpointInterval: GetDefaultLocal().CatchpointInterval,
			archival:           GetDefaultLocal().Archival,
			expected:           false,
		},
		{
			name:               "0 expects false",
			catchpointTracking: CatchpointTrackingModeAutomatic,
			catchpointInterval: GetDefaultLocal().CatchpointInterval,
			archival:           GetDefaultLocal().Archival,
			expected:           false,
		},
		{
			name:               "0 w/ archival expects true",
			catchpointTracking: CatchpointTrackingModeAutomatic,
			catchpointInterval: GetDefaultLocal().CatchpointInterval,
			archival:           true,
			expected:           true,
		},
		{
			name:               "0 w/ archival & catchpointInterval=0 expects false",
			catchpointTracking: CatchpointTrackingModeAutomatic,
			catchpointInterval: 0,
			archival:           true,
			expected:           false,
		},
		{
			name:               "1 expects false",
			catchpointTracking: CatchpointTrackingModeTracked,
			catchpointInterval: GetDefaultLocal().CatchpointInterval,
			archival:           GetDefaultLocal().Archival,
			expected:           false,
		},
		{
			name:               "1 w/ archival expects true",
			catchpointTracking: CatchpointTrackingModeTracked,
			catchpointInterval: GetDefaultLocal().CatchpointInterval,
			archival:           true,
			expected:           true,
		},
		{
			name:               "1 w/ archival & catchpointInterval=0 expects false",
			catchpointTracking: CatchpointTrackingModeTracked,
			catchpointInterval: 0,
			archival:           true,
			expected:           false,
		},
		{
			name:               "2 w/ catchpointInterval=0 expects false",
			catchpointTracking: CatchpointTrackingModeStored,
			catchpointInterval: 0,
			archival:           GetDefaultLocal().Archival,
			expected:           false,
		},
		{
			name:               "2 expects true",
			catchpointTracking: CatchpointTrackingModeStored,
			catchpointInterval: GetDefaultLocal().CatchpointInterval,
			archival:           GetDefaultLocal().Archival,
			expected:           true,
		},
		{
			name:               "99 expects false",
			catchpointTracking: 99,
			catchpointInterval: GetDefaultLocal().CatchpointInterval,
			archival:           GetDefaultLocal().Archival,
			expected:           false,
		},
		{
			name:               "99 w/ catchpointInterval=0 expects false",
			catchpointTracking: 99,
			catchpointInterval: 0,
			archival:           GetDefaultLocal().Archival,
			expected:           false,
		},
		{
			name:               "27 expects false",
			catchpointTracking: 27,
			catchpointInterval: GetDefaultLocal().CatchpointInterval,
			archival:           GetDefaultLocal().Archival,
			expected:           false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := GetDefaultLocal()
			cfg.CatchpointTracking = test.catchpointTracking
			cfg.CatchpointInterval = test.catchpointInterval
			cfg.Archival = test.archival
			require.Equal(t, test.expected, cfg.StoresCatchpoints())
			if cfg.StoresCatchpoints() {
				require.Equal(t, true, cfg.TracksCatchpoints())
			}
		})
	}
}

func TestTracksCatchpointsWithoutStoring(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := GetDefaultLocal()
	cfg.CatchpointTracking = CatchpointTrackingModeTracked
	cfg.CatchpointInterval = 10000
	cfg.Archival = false
	require.Equal(t, true, cfg.TracksCatchpoints())
	require.Equal(t, false, cfg.StoresCatchpoints())
}
