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

package kmd

import (
	"os"
	"time"

	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/server"
	"github.com/algorand/go-algorand/daemon/kmd/session"
	"github.com/algorand/go-algorand/daemon/kmd/wallet/driver"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/tokens"
)

// StartConfig contains configuration information used for starting up kmd
type StartConfig struct {
	// DataDir is the kmd data directory, used to store config info and
	// some kinds of wallets
	DataDir string
	// Kill takes an os.Signal and gracefully shuts down the kmd process
	Kill chan os.Signal
	// Log logs information about the running kmd process
	Log logging.Logger
	// Timeout is the duration of time after which we will kill the kmd
	// process automatically. If Timeout is nil, we will never time out.
	Timeout *time.Duration
}

// Start loads kmd's configuration information, initializes all of its
// services, and starts the API HTTP server
func Start(startConfig StartConfig) (died chan error, sock string, err error) {
	// Load the global KMD configuration
	kmdCfg, err := config.LoadKMDConfig(startConfig.DataDir)
	if err != nil {
		return
	}

	// Initialize wallet drivers with the config
	err = driver.InitWalletDrivers(kmdCfg, startConfig.Log)
	if err != nil {
		return
	}

	// Make or read the API token + check that it's reasonable
	apiToken, _, err := tokens.ValidateOrGenerateAPIToken(startConfig.DataDir, tokens.KmdTokenFilename)
	if err != nil {
		return
	}

	// Configure the wallet API server
	serverCfg := server.WalletServerConfig{
		APIToken:       apiToken,
		DataDir:        startConfig.DataDir,
		Address:        kmdCfg.Address,
		AllowedOrigins: kmdCfg.AllowedOrigins,
		SessionManager: session.MakeManager(kmdCfg),
		Log:            startConfig.Log,
		Timeout:        startConfig.Timeout,
	}

	// Instantiate the wallet API server
	ws, err := server.MakeWalletServer(serverCfg)
	if err != nil {
		return
	}

	// Start the wallet API server
	died, sock, err = ws.Start(startConfig.Kill)
	return
}
