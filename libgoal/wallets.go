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

package libgoal

import (
	"bytes"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
)

const (
	defaultWalletDriver = "sqlite"
)

// CreateWallet creates a kmd wallet with the specified parameters
func (c *Client) CreateWallet(name []byte, password []byte, mdk crypto.MasterDerivationKey) ([]byte, error) {
	// Pull the list of all wallets from kmd
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return nil, err
	}

	// Create the wallet
	resp, err := kmd.CreateWallet(name, defaultWalletDriver, password, mdk)
	if err != nil {
		return nil, err
	}

	return []byte(resp.Wallet.ID), nil
}

// GetWalletHandleToken inits the wallet with the given id, returning a wallet handle token
func (c *Client) GetWalletHandleToken(wid, pw []byte) ([]byte, error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return nil, err
	}

	// Initialize the wallet
	resp, err := kmd.InitWallet(wid, pw)
	if err != nil {
		return nil, err
	}

	// Return the handle token from the response
	return []byte(resp.WalletHandleToken), nil
}

// WalletIsUnencrypted is a helper that checks if the passed wallet ID requires
// a password. This function will also return false if there are any other
// errors when contacting kmd. TODO: return errors when the kmd API has proper
// error codes
func (c *Client) WalletIsUnencrypted(wid []byte) bool {
	wh, err := c.GetWalletHandleToken(wid, nil)
	if err != nil {
		// There was an error initializing the wallet; assume it
		// requires a password
		return false
	}
	// We were able to initialize the wallet, it definitely doesn't require
	// a password
	defer c.ReleaseWalletHandle(wh)
	return true
}

// GetWalletHandleTokenCached first checks the cache for a valid token for this wallet
// and renews it if possible. If there aren't any valid cached tokens, it generates
// a new one and adds it to the cache.
func (c *Client) GetWalletHandleTokenCached(walletID, pw []byte) ([]byte, error) {
	if c.cacheDir == "" {
		return nil, fmt.Errorf("libgoal not initialized with cacheDir")
	}

	// Try the cache
	wht, err := loadWalletHandleFromDisk(walletID, c.cacheDir)
	if err != nil {
		return nil, err
	}

	// Was there a token in the cache?
	if len(wht) > 0 {
		// Try to renew it
		valid := c.checkHandleValidMaybeRenew(wht)
		if valid {
			return wht, nil
		}
	}

	// Make a new token
	wht, err = c.GetWalletHandleToken(walletID, pw)
	if err != nil {
		return nil, err
	}

	// Add it to the cache
	err = writeWalletHandleToDisk(wht, walletID, c.cacheDir)
	if err != nil {
		return nil, err
	}

	return wht, nil
}

// ReleaseWalletHandle invalidates the passed wallet handle token
func (c *Client) ReleaseWalletHandle(wh []byte) error {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return err
	}

	// Release the wallet handle
	_, err = kmd.ReleaseWalletHandle(wh)
	return err
}

// ListWallets returns the list of wallets that kmd is aware of
func (c *Client) ListWallets() (wallets []kmdapi.APIV1Wallet, err error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	// List the wallets
	resp, err := kmd.ListWallets()
	if err != nil {
		return
	}

	// Return the wallets slice
	return resp.Wallets, nil
}

// FindWalletIDByName searches the list of wallets for one with the passed name,
// and returns its ID. If there is more than one wallet with the passed name,
// it sets duplicate to true.
func (c *Client) FindWalletIDByName(name []byte) (wid []byte, duplicate bool, err error) {
	// Pull the list of all wallets from kmd
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	resp, err := kmd.ListWallets()
	if err != nil {
		return
	}

	// For each wallet, check for a match, and indicate if we've found a duplicate
	for _, wallet := range resp.Wallets {
		if bytes.Equal([]byte(wallet.Name), name) {
			// Found a matching wallet
			if wid != nil {
				duplicate = true
			}
			wid = []byte(wallet.ID)
		}
	}

	return
}

// FindWalletNameByID searches the list of wallets for one with the passed ID,
// and returns its name. If there is more than one wallet with the passed ID,
// it sets duplicate to true.
func (c *Client) FindWalletNameByID(wid []byte) (name []byte, duplicate bool, err error) {
	// Pull the list of all wallets from kmd
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	resp, err := kmd.ListWallets()
	if err != nil {
		return
	}

	// For each wallet, check for a match, and indicate if we've found a duplicate
	for _, wallet := range resp.Wallets {
		if bytes.Equal([]byte(wallet.ID), wid) {
			// Found a matching wallet
			if name != nil {
				duplicate = true
			}
			name = []byte(wallet.Name)
		}
	}

	return
}

// ExportMasterDerivationKey returns the master derivation key from the given wallet
func (c *Client) ExportMasterDerivationKey(wh []byte, pw []byte) (mdk crypto.MasterDerivationKey, err error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	// Export the master derivation key
	resp, err := kmd.ExportMasterDerivationKey(wh, pw)
	if err != nil {
		return
	}

	// Return the mdk from the response
	return resp.MasterDerivationKey, nil
}
