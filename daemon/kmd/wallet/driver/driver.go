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

package driver

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/wallet"
	"github.com/algorand/go-algorand/logging"
)

var walletDrivers = map[string]Driver{
	sqliteWalletDriverName: &SQLiteWalletDriver{},
	ledgerWalletDriverName: &LedgerWalletDriver{},
}

// Driver is the interface that all wallet drivers must expose in order to be
// compatible with kmd. In particular, wallet drivers must be able to
// initialize themselves from a Config, create a wallet with a name, ID,
// and password, and fetch a wallet by ID.
type Driver interface {
	InitWithConfig(cfg config.KMDConfig, log logging.Logger) error
	ListWalletMetadatas() ([]wallet.Metadata, error)
	CreateWallet(name []byte, id []byte, pw []byte, mdk crypto.MasterDerivationKey) error
	RenameWallet(newName []byte, id []byte, pw []byte) error
	FetchWallet(id []byte) (wallet.Wallet, error)
}

// InitWalletDrivers accepts a KMDConfig and uses it to initialize each driver
func InitWalletDrivers(cfg config.KMDConfig, log logging.Logger) error {
	for _, driver := range walletDrivers {
		err := driver.InitWithConfig(cfg, log)
		if err != nil {
			return err
		}
	}
	return nil
}

// FetchWalletDriver accepts a driver name and returns a corresponding instance
// of the appropriate wallet driver, or nil
func FetchWalletDriver(driverName string) (Driver, error) {
	d := walletDrivers[driverName]
	if d == nil {
		return nil, fmt.Errorf("unknown wallet driver")
	}
	return d, nil
}

// ListWalletMetadatas fetches wallet metadata from all of the drivers
func ListWalletMetadatas() ([]wallet.Metadata, error) {
	var metadatas []wallet.Metadata

	// Iterate over the wallet drivers
	for _, driver := range walletDrivers {
		// Fetch all of the WalletMetadatas for each driver
		driverMetadatas, err := driver.ListWalletMetadatas()
		if err != nil {
			return nil, err
		}
		// Append them to the result
		metadatas = append(metadatas, driverMetadatas...)
	}

	return metadatas, nil
}

// FetchWalletByID iterates over the wallet drivers and returns a wallet with
// the passed ID
func FetchWalletByID(id []byte) (wallet.Wallet, error) {
	var matches []wallet.Wallet
	// Iterate over the wallet drivers
	for _, driver := range walletDrivers {
		result, err := driver.FetchWallet(id)
		if err != nil && err != errWalletNotFound {
			return nil, err
		} else if err == nil {
			matches = append(matches, result)
		}
	}

	// Ensure there was exactly one match
	numMatches := len(matches)
	if numMatches == 0 {
		return nil, errWalletNotFound
	} else if numMatches == 1 {
		return matches[0], nil
	}

	// Otherwise, there's at least one ID conflict
	return nil, errIDConflict
}

// ListWalletDriverNames returns a list of names of the wallet drivers that kmd
// is aware of
func ListWalletDriverNames() []string {
	var drivers []string
	for name := range walletDrivers {
		drivers = append(drivers, name)
	}
	return drivers
}
