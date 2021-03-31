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

package fixtures

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/kmd/client"
	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/util"
)

// defaultConfig lowers scrypt params to make tests faster
var defaultConfig = `{"drivers":{"sqlite":{"scrypt":{"scrypt_n":2},"allow_unsafe_scrypt":true}}}`

// shutdownTimeoutSecs is time to wait for kmd to shut down before returning an error
const shutdownTimeoutSecs = 5

// defaultTimeoutSecs is the number of seconds after which kmd will die if it
// receives no requests
const defaultTimeoutSecs = 60

var defaultWalletName = "default"
var defaultWalletPassword = "hunter2"
var defaultWalletDriver = "sqlite"
var defaultAPIToken = []byte(strings.Repeat("a", 64))

// KMDFixture is a test fixture for tests requiring interactions with kmd
type KMDFixture struct {
	baseFixture
	t              TestingTB
	initialized    bool
	dataDir        string
	kmdDir         string
	Sock           string
	APIToken       []byte
	WalletName     string
	WalletPassword string
	Client         *client.KMDClient
}

// Run runs all of the tests for this fixture
func (f *KMDFixture) Run(m *testing.M) int {
	return f.run(m)
}

// RunAndExit is like Run, but then calls ShutdownImpl
func (f *KMDFixture) RunAndExit(m *testing.M) {
	f.runAndExit(m)
}

// Shutdown stops the kmd instance if it's running and cleans up the dataDir if
// there was no test failure
func (f *KMDFixture) Shutdown() {
	// If there's a kmd server running
	if f.initialized {
		nc := nodecontrol.MakeNodeController(f.binDir, f.dataDir)
		nc.SetKMDDataDir(f.kmdDir)
		_, err := nc.StopKMD()
		require.NoError(f.t, err)
	}

	// Clean up test folder if there was no failure
	if !f.t.Failed() {
		os.RemoveAll(f.dataDir)
	}
}

// ShutdownImpl is not relevant for kmd so just panics
func (f *KMDFixture) ShutdownImpl(preserveData bool) {
	panic("ShutdownImpl not supported for *KMDFixture")
}

// SetupWithWallet starts kmd and creates a wallet, returning a wallet handle
func (f *KMDFixture) SetupWithWallet(t TestingTB) (handleToken string) {
	f.Setup(t)
	handleToken, _ = f.MakeWalletAndHandleToken()
	return
}

// Setup starts kmd with the default config
func (f *KMDFixture) Setup(t TestingTB) {
	f.SetupWithConfig(t, "")
}

// Initialize initializes the dataDir and TestingT for this test but doesn't start kmd
func (f *KMDFixture) Initialize(t TestingTB) {
	f.initialize(f)
	f.t = SynchronizedTest(t)
	f.dataDir = filepath.Join(f.testDir, t.Name())
	// Remove any existing tests in this dataDir + recreate
	err := os.RemoveAll(f.dataDir)
	require.NoError(f.t, err)
	err = os.Mkdir(f.dataDir, 0750)
	require.NoError(f.t, err)

	// Set up the kmd data dir within the main datadir
	f.kmdDir = filepath.Join(f.dataDir, nodecontrol.DefaultKMDDataDir)
	err = os.Mkdir(f.kmdDir, nodecontrol.DefaultKMDDataDirPerms)
	require.NoError(f.t, err)
}

// SetupWithConfig starts a kmd node with the passed config or default test
// config, if the passed config is blank. Though internally an error might
// occur during setup, we never return one, because we'll still fail the test
// for any errors here, and it keeps the test code much cleaner
func (f *KMDFixture) SetupWithConfig(t TestingTB, config string) {
	// Setup is called once per test, so it's OK for test to store one particular TestingT
	f.Initialize(t)

	// Write a token
	f.APIToken = defaultAPIToken
	tokenFilepath := filepath.Join(f.kmdDir, "kmd.token")
	err := ioutil.WriteFile(tokenFilepath, f.APIToken, 0640)
	require.NoError(f.t, err)

	if config == "" {
		config = defaultConfig
	}
	configFilepath := filepath.Join(f.kmdDir, "kmd_config.json")
	err = ioutil.WriteFile(configFilepath, []byte(config), 0640)
	require.NoError(f.t, err)

	// Start kmd
	nc := nodecontrol.MakeNodeController(f.binDir, f.dataDir)
	nc.SetKMDDataDir(f.kmdDir)
	_, err = nc.StartKMD(nodecontrol.KMDStartArgs{
		TimeoutSecs: defaultTimeoutSecs,
	})
	require.NoError(f.t, err)

	// Mark ourselves as initialized so we know to shut down server
	f.initialized = true

	// Build a client
	sock, err := util.GetFirstLineFromFile(filepath.Join(f.kmdDir, "kmd.net"))
	require.NoError(f.t, err)
	f.Sock = sock
	client, err := client.MakeKMDClient(f.Sock, string(f.APIToken))
	require.NoError(f.t, err)
	f.Client = &client
}

// MakeWalletAndHandleToken creates a wallet and returns a wallet handle to it
func (f *KMDFixture) MakeWalletAndHandleToken() (handleToken string, err error) {
	// Create a wallet
	req0 := kmdapi.APIV1POSTWalletRequest{
		WalletName:       defaultWalletName,
		WalletPassword:   defaultWalletPassword,
		WalletDriverName: defaultWalletDriver,
	}

	// We only ever associate one wallet with a fixture
	f.WalletPassword = defaultWalletPassword
	f.WalletName = defaultWalletName

	resp0 := kmdapi.APIV1POSTWalletResponse{}
	err = f.Client.DoV1Request(req0, &resp0)
	require.NoError(f.t, err)

	// Get a wallet token
	req1 := kmdapi.APIV1POSTWalletInitRequest{
		WalletID:       resp0.Wallet.ID,
		WalletPassword: defaultWalletPassword,
	}
	resp1 := kmdapi.APIV1POSTWalletInitResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	require.NoError(f.t, err)

	// Return the token
	return resp1.WalletHandleToken, nil
}

// TestConfig checks whether or not the passed config would be considered valid
func (f *KMDFixture) TestConfig(cfg []byte) error {
	// Write the passed config
	configFilepath := filepath.Join(f.kmdDir, "kmd_config.json")
	err := ioutil.WriteFile(configFilepath, cfg, 0640)
	if err != nil {
		return err
	}
	// Check it with the config package
	_, err = config.LoadKMDConfig(f.kmdDir)
	return err
}
