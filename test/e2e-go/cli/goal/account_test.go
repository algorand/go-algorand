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

package goal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

const statusOffline = "[offline]"
const statusOnline = "[online]"

func TestAccountNew(t *testing.T) {
	defer fixture.SetTestContext(t)()
	a := require.New(t)

	newAcctName := "new_account"

	// Verify the account doesn't exist before we create it
	matched, err := fixture.CheckAccountListContainsAccount(func(elements []string) bool {
		return elements[1] == newAcctName
	})
	a.False(matched, "account name shouldn't be in use yet")

	addr, err := fixture.AccountNew(newAcctName)
	a.NoError(err)
	a.NotEmpty(addr)

	matched, err = fixture.CheckAccountListContainsAccount(func(elements []string) bool {
		return elements[0] == statusOffline &&
			elements[1] == newAcctName &&
			elements[2] == addr
	})
	a.NoError(err)
	a.True(matched, "Account list should contain the account we just created")
}

func TestAccountNewDuplicateFails(t *testing.T) {
	defer fixture.SetTestContext(t)()
	a := require.New(t)

	newAcctName := "duplicate_account"

	addr, err := fixture.AccountNew(newAcctName)
	a.NoError(err)
	a.NotEmpty(addr)

	addr, err = fixture.AccountNew(newAcctName)
	a.Empty(addr, "no address should be returned when trying to add a duplicate account")
	a.Equal(fixtures.ErrAccountAlreadyTaken, err)
}

func TestAccountRename(t *testing.T) {
	defer fixture.SetTestContext(t)()
	a := require.New(t)

	initialAcctName := "initial"
	newAcctName := "renamed"
	addr, err := fixture.AccountNew(initialAcctName)
	a.NoError(err)
	a.NotEmpty(addr)

	// Verify the account doesn't exist before we create it
	matched, err := fixture.CheckAccountListContainsAccount(func(elements []string) bool {
		return elements[1] == newAcctName
	})
	a.NoError(err)
	a.False(matched, "new account name shouldn't be in use yet")

	err = fixture.AccountRename(initialAcctName, newAcctName)
	a.NoError(err)

	matched, err = fixture.CheckAccountListContainsAccount(func(elements []string) bool {
		return elements[0] == statusOffline &&
			elements[1] == newAcctName &&
			elements[2] == addr
	})
	a.NoError(err)
	a.True(matched, "Account list should contain the account we just created, with the new name")
}

// Importing an account multiple times should not be considered an error by goal
func TestAccountMultipleImportRootKey(t *testing.T) {
	defer fixture.SetTestContext(t)()
	a := require.New(t)

	walletName := ""
	createUnencryptedWallet := false
	err := fixture.AccountImportRootKey(walletName, createUnencryptedWallet)
	a.NoError(err)

	err = fixture.AccountImportRootKey(walletName, createUnencryptedWallet)
	a.NoError(err)
}
