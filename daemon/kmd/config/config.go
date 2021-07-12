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

package config

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/algorand/go-algorand/util/codecs"
)

const (
	kmdConfigFilename          = "kmd_config.json"
	kmdConfigExampleFilename   = kmdConfigFilename + ".example"
	defaultSessionLifetimeSecs = 60
	defaultScryptN             = 65536
	defaultScryptR             = 1
	defaultScryptP             = 32
)

// KMDConfig contains global configuration information for kmd
type KMDConfig struct {
	DataDir             string       `json:"-"`
	DriverConfig        DriverConfig `json:"drivers"`
	SessionLifetimeSecs uint64       `json:"session_lifetime_secs"`
	Address             string       `json:"address"`
	AllowedOrigins      []string     `json:"allowed_origins"`
}

// DriverConfig contains config info specific to each wallet driver
type DriverConfig struct {
	SQLiteWalletDriverConfig SQLiteWalletDriverConfig `json:"sqlite"`
	LedgerWalletDriverConfig LedgerWalletDriverConfig `json:"ledger"`
}

// SQLiteWalletDriverConfig is configuration specific to the SQLiteWalletDriver
type SQLiteWalletDriverConfig struct {
	WalletsDir   string       `json:"wallets_dir"`
	UnsafeScrypt bool         `json:"allow_unsafe_scrypt"`
	ScryptParams ScryptParams `json:"scrypt"`
}

// LedgerWalletDriverConfig is configuration specific to the LedgerWalletDriver
type LedgerWalletDriverConfig struct {
	Disable bool `json:"disable"`
}

// ScryptParams stores the parameters used for key derivation. This allows
// upgrading security parameters over time
type ScryptParams struct {
	ScryptN int `json:"scrypt_n"`
	ScryptR int `json:"scrypt_r"`
	ScryptP int `json:"scrypt_p"`
}

// defaultConfig returns the default KMDConfig
func defaultConfig(dataDir string) KMDConfig {
	return KMDConfig{
		DataDir:             dataDir,
		SessionLifetimeSecs: defaultSessionLifetimeSecs,
		DriverConfig: DriverConfig{
			SQLiteWalletDriverConfig: SQLiteWalletDriverConfig{
				ScryptParams: ScryptParams{
					ScryptN: defaultScryptN,
					ScryptR: defaultScryptR,
					ScryptP: defaultScryptP,
				},
			},
		},
	}
}

// Validate ensures that the current configuration is valid, returning an error
// if it's not
func (k KMDConfig) Validate() error {
	// If a SQLite Wallet directory is passed, ensure that it is absolute
	sqlWalletsDir := k.DriverConfig.SQLiteWalletDriverConfig.WalletsDir
	if sqlWalletsDir != "" {
		if !filepath.IsAbs(sqlWalletsDir) {
			return ErrSQLiteWalletNotAbsolute
		}
	}
	return nil
}

// LoadKMDConfig tries to read the the kmd configuration from disk, merging the
// default kmd configuration with what it finds
func LoadKMDConfig(dataDir string) (cfg KMDConfig, err error) {
	cfg = defaultConfig(dataDir)
	configFilename := filepath.Join(dataDir, kmdConfigFilename)
	dat, err := ioutil.ReadFile(configFilename)
	// If there is no config file, then return the default configuration, and dump the default config to disk
	if err != nil {
		exampleFilename := filepath.Join(dataDir, kmdConfigExampleFilename)
		// SaveObjectToFile may return an unhandled error because
		// there is nothing to do if an error occurs
		codecs.SaveObjectToFile(exampleFilename, cfg, true)
		return cfg, nil
	}
	// Fill in the non-default values
	err = json.Unmarshal(dat, &cfg)
	if err != nil {
		return
	}
	err = cfg.Validate()
	return
}
