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

package session

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"regexp"
	"time"

	"github.com/algorand/go-algorand/daemon/kmd/wallet"
)

const (
	wHandleIDBytes       = 8
	wHandleSecretBytes   = 32
	handleCleanupSeconds = 60
)

var wHandleTokenSplitChar = []byte(".")
var wHandleIDRegex = regexp.MustCompile(`^[0-9a-f]{16}$`)
var wHandleSecretRegex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validateHandleID(handleID []byte) error {
	if wHandleIDRegex.Find(handleID) == nil {
		return fmt.Errorf("invalid wallet handle id")
	}
	return nil
}

func validateHandleSecret(handleSecret []byte) error {
	if wHandleSecretRegex.Find(handleSecret) == nil {
		return fmt.Errorf("invalid wallet handle secret")
	}
	return nil
}

func splitHandle(walletHandle []byte) ([]byte, []byte, error) {
	split := bytes.SplitN(walletHandle, wHandleTokenSplitChar, 2)

	if len(split) != 2 {
		return nil, nil, fmt.Errorf("wrong number of token parts")
	}

	handleID := split[0]
	handleSecret := split[1]

	err := validateHandleID(handleID)
	if err != nil {
		return nil, nil, err
	}

	err = validateHandleSecret(handleSecret)
	if err != nil {
		return nil, nil, err
	}

	return handleID, handleSecret, nil
}

func checkHandleNotExpired(expires time.Time) error {
	if time.Now().After(expires) {
		return fmt.Errorf("handle expired")
	}
	return nil
}

func generateHandleIDAndSecret() ([]byte, []byte, error) {
	handleID := make([]byte, wHandleIDBytes)
	_, err := rand.Read(handleID)
	if err != nil {
		return nil, nil, err
	}

	handleSecret := make([]byte, wHandleSecretBytes)
	_, err = rand.Read(handleSecret)
	if err != nil {
		return nil, nil, err
	}

	hexID := []byte(fmt.Sprintf("%x", handleID))
	hexSecret := []byte(fmt.Sprintf("%x", handleSecret))
	return hexID, hexSecret, nil
}

// cleanUpExpiredHandlesLocked periodically calls deleteExpiredHandles until
// sm.ctx is canceled.
func (sm *Manager) cleanUpExpiredHandles() {
	ticker := time.NewTicker(handleCleanupSeconds * time.Second)
	for {
		select {
		case <-ticker.C:
			sm.deleteExpiredHandles()
		case <-sm.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

// deleteExpiredHandles is a helper for cleanUpExpiredHandles. It periodically
// iterates over the walletHandles map and deletes ones that have expired
func (sm *Manager) deleteExpiredHandles() {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	for handleID, handle := range sm.walletHandles {
		if checkHandleNotExpired(handle.expires) != nil {
			delete(sm.walletHandles, handleID)
		}
	}
}

// InitWalletHandle attempts to init the wallet using the passed password,
// generates a wallet handle token, and adds the session to the memory store
func (sm *Manager) InitWalletHandle(w wallet.Wallet, pw []byte) ([]byte, error) {
	// Attempt to initialize the wallet with the password
	err := w.Init(pw)
	if err != nil {
		return nil, err
	}

	// Generate wallet handle credentials
	handleID, handleSecret, err := generateHandleIDAndSecret()
	if err != nil {
		return nil, err
	}

	// Build the walletHandle
	handle := walletHandle{
		secret:  handleSecret,
		expires: time.Now().Add(sm.sessionLifetime),
		wallet:  w,
	}

	// Insert the handle into the walletHandles map
	sm.mux.Lock()
	defer sm.mux.Unlock()
	sm.walletHandles[string(handleID)] = handle
	handleToken := []byte(fmt.Sprintf("%s%s%s", handleID, wHandleTokenSplitChar, handleSecret))

	return handleToken, nil
}

// getHandleFromTokenLocked is a helper that looks up the wallet handle from
// the token and checks that the token secret is correct. If it is, it returns
// the handle ID and the handle itself
func (sm *Manager) getHandleFromTokenLocked(walletHandleToken []byte) (id []byte, wh walletHandle, err error) {
	// Ensure the token is a valid format
	handleID, handleSecret, err := splitHandle(walletHandleToken)
	if err != nil {
		return
	}

	// Fetch the handle if it exists
	handle, ok := sm.walletHandles[string(handleID)]
	if !ok {
		err = fmt.Errorf("handle does not exist")
		return
	}

	// Check that the token is correct in constant time
	if subtle.ConstantTimeCompare(handleSecret, handle.secret) != 1 {
		err = fmt.Errorf("invalid token")
		return
	}

	return handleID, handle, err
}

// ReleaseWalletHandle deletes the wallet handle if it exists
func (sm *Manager) ReleaseWalletHandle(walletHandleToken []byte) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()

	// Fetch the handle + check that the token is correct
	handleID, _, err := sm.getHandleFromTokenLocked(walletHandleToken)
	if err != nil {
		return err
	}

	// Delete the handle
	delete(sm.walletHandles, string(handleID))
	return nil
}

// authMaybeRenewWalletHandleToken parses an untrusted walletHandle []byte and
// returns the Wallet it corresponds to + seconds until expiration if and only
// if the walletHandle was valid. If `renew` is true, it also renews the token
func (sm *Manager) authMaybeRenewWalletHandleToken(walletHandleToken []byte, renew bool) (wallet.Wallet, int64, error) {
	sm.mux.Lock()
	defer sm.mux.Unlock()

	// Fetch the handle + check that the token is correct
	handleID, handle, err := sm.getHandleFromTokenLocked(walletHandleToken)
	if err != nil {
		return nil, 0, err
	}

	// Check that the handle has not expired
	err = checkHandleNotExpired(handle.expires)
	if err != nil {
		// It's expired, so delete it
		delete(sm.walletHandles, string(handleID))
		return nil, 0, err
	}

	// Maybe renew the handle
	if renew {
		handle.expires = time.Now().Add(sm.sessionLifetime)
		sm.walletHandles[string(handleID)] = handle
	}

	// Compute how many seconds are left until the handle expires
	expiresSeconds := int64(handle.expires.Sub(time.Now()).Seconds())

	// Return the wallet and seconds remaining to expiration
	return handle.wallet, expiresSeconds, nil
}

// RenewWalletHandleToken parses an untrusted walletHandle []byte and renews it
// if the secret is correct and if it hasn't already expired
func (sm *Manager) RenewWalletHandleToken(walletHandleToken []byte) (wallet.Wallet, int64, error) {
	return sm.authMaybeRenewWalletHandleToken(walletHandleToken, true)
}

// AuthWithWalletHandleToken parses an untrusted walletHandle []byte and
// returns the Wallet it corresponds to + seconds until expiration if and only
// if the walletHandle was valid.
func (sm *Manager) AuthWithWalletHandleToken(walletHandleToken []byte) (wallet.Wallet, int64, error) {
	return sm.authMaybeRenewWalletHandleToken(walletHandleToken, false)
}
