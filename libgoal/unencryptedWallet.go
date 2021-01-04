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
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
)

var unencryptedWalletDriver = "sqlite"

// UnencryptedWalletName is the name of the default, unencrypted wallet
var UnencryptedWalletName = []byte("unencrypted-default-wallet")

// SendPaymentFromUnencryptedWallet signs a transaction using the default wallet and returns the resulted transaction id
func (c *Client) SendPaymentFromUnencryptedWallet(from, to string, fee, amount uint64, note []byte) (transactions.Transaction, error) {
	wh, err := c.GetUnencryptedWalletHandle()
	if err != nil {
		return transactions.Transaction{}, err
	}

	return c.SendPaymentFromWallet(wh, nil, from, to, fee, amount, note, "", 0, 0)
}

// GetUnencryptedWalletHandle returns the unencrypted wallet handle. If there
// is no unencrypted wallet, it creates one first.
// This should never be used outside of tests, because it creates a wallet named
// unencrypted-default-wallet if it doesn't exist.
func (c *Client) GetUnencryptedWalletHandle() ([]byte, error) {
	useCacheDir := c.cacheDir != ""
	return c.getUnencryptedWalletHandle(useCacheDir)
}

func (c *Client) getUnencryptedWalletHandle(cached bool) ([]byte, error) {
	// Determine the default wallet ID
	id, err := c.getMaybeCreateUnencryptedWallet()
	if err != nil {
		return nil, err
	}

	if cached {
		return c.GetWalletHandleTokenCached(id, nil)
	}

	return c.GetWalletHandleToken(id, nil)
}

func (c *Client) getMaybeCreateUnencryptedWallet() ([]byte, error) {
	// Check if the default wallet already exists
	defaultWalletID, duplicate, err := c.FindWalletIDByName(UnencryptedWalletName)
	if err != nil {
		return nil, err
	}
	if duplicate {
		return nil, fmt.Errorf("multiple default unencrypted wallets exist")
	}

	// Not found -- create it
	if defaultWalletID == nil {
		kmd, err := c.ensureKmdClient()
		if err != nil {
			return nil, err
		}

		resp, err := kmd.CreateWallet(UnencryptedWalletName, unencryptedWalletDriver, nil, crypto.MasterDerivationKey{})
		if err != nil {
			return nil, err
		}
		defaultWalletID = []byte(resp.Wallet.ID)
	}

	return defaultWalletID, nil
}

// UnencryptedMultisigSignTransaction is MultisigSignTransactionWithWallet for the default wallet
func (c *Client) UnencryptedMultisigSignTransaction(utx transactions.Transaction, signerAddr string, partial crypto.MultisigSig) (msig crypto.MultisigSig, err error) {
	wh, err := c.GetUnencryptedWalletHandle()
	if err != nil {
		return
	}
	return c.MultisigSignTransactionWithWallet(wh, nil, utx, signerAddr, partial)
}
