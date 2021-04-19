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

package kmdtest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestWalletCreation(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	f.Setup(t)
	defer f.Shutdown()

	// Test that `GET /v1/wallets` returns no wallets
	req0 := kmdapi.APIV1GETWalletsRequest{}
	resp0 := kmdapi.APIV1GETWalletsResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Shouldn't be any wallets yet
	a.Equal(len(resp0.Wallets), 0)

	// Create a wallet
	walletName := "default"
	password := "password"
	req1 := kmdapi.APIV1POSTWalletRequest{
		WalletName:       walletName,
		WalletPassword:   password,
		WalletDriverName: "sqlite",
	}
	resp1 := kmdapi.APIV1POSTWalletResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// Test that `GET /v1/wallets` returns the new wallet
	req2 := kmdapi.APIV1GETWalletsRequest{}
	resp2 := kmdapi.APIV1GETWalletsResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	// Should be one wallet
	a.Equal(len(resp2.Wallets), 1)

	// Try to create a wallet with the same name
	req3 := kmdapi.APIV1POSTWalletRequest{
		WalletName:       walletName,
		WalletPassword:   password,
		WalletDriverName: "sqlite",
	}
	resp3 := kmdapi.APIV1POSTWalletResponse{}
	err = f.Client.DoV1Request(req3, &resp3)

	// Should be an error
	a.Error(err)
}

func TestBlankWalletCreation(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	f.Setup(t)
	defer f.Shutdown()

	// Create a wallet with a blank name
	req0 := kmdapi.APIV1POSTWalletRequest{
		WalletName:       "",
		WalletPassword:   f.WalletPassword,
		WalletDriverName: "sqlite",
	}
	resp0 := kmdapi.APIV1POSTWalletResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Test that `GET /v1/wallets` returns the new wallet
	req1 := kmdapi.APIV1GETWalletsRequest{}
	resp1 := kmdapi.APIV1GETWalletsResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// Should be one wallet
	a.Equal(len(resp1.Wallets), 1)

	// Name should not be blank
	a.NotEmpty(resp1.Wallets[0].Name)

	// Name should be equal to ID
	a.Equal(resp1.Wallets[0].Name, resp1.Wallets[0].ID)
}

func TestWalletRename(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	f.Setup(t)
	defer f.Shutdown()

	// Create a wallet
	walletName := "default"
	password := "password"
	req0 := kmdapi.APIV1POSTWalletRequest{
		WalletName:       walletName,
		WalletPassword:   password,
		WalletDriverName: "sqlite",
	}
	resp0 := kmdapi.APIV1POSTWalletResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Test that `GET /v1/wallets` returns the new wallet
	req1 := kmdapi.APIV1GETWalletsRequest{}
	resp1 := kmdapi.APIV1GETWalletsResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// Should be one wallet
	a.Equal(len(resp1.Wallets), 1)

	// Name should be correct
	a.Equal(resp1.Wallets[0].Name, walletName)

	// Try to rename the wallet with the wrong password
	newWalletName := "newWallet4u"
	req2 := kmdapi.APIV1POSTWalletRenameRequest{
		WalletID:       resp1.Wallets[0].ID,
		NewWalletName:  newWalletName,
		WalletPassword: "wr0ng_p4ssw0rd",
	}
	resp2 := kmdapi.APIV1POSTWalletRenameResponse{}
	err = f.Client.DoV1Request(req2, &resp2)

	// Should be an error
	a.Error(err)

	// Try to rename the wallet with the correct password
	req3 := kmdapi.APIV1POSTWalletRenameRequest{
		WalletID:       resp1.Wallets[0].ID,
		NewWalletName:  newWalletName,
		WalletPassword: password,
	}
	resp3 := kmdapi.APIV1POSTWalletRenameResponse{}
	err = f.Client.DoV1Request(req3, &resp3)

	// Should succeed
	a.NoError(err)

	// Returned wallet should have the new name
	a.Equal(newWalletName, resp3.Wallet.Name)

	// Returned wallet should have the correct ID
	a.Equal(resp1.Wallets[0].ID, resp3.Wallet.ID)

	// Test that `GET /v1/wallets` returns the new wallet
	req4 := kmdapi.APIV1GETWalletsRequest{}
	resp4 := kmdapi.APIV1GETWalletsResponse{}
	err = f.Client.DoV1Request(req4, &resp4)
	a.NoError(err)

	// Should be one wallet
	a.Equal(len(resp4.Wallets), 1)

	// Returned wallet should have the new name
	a.Equal(newWalletName, resp4.Wallets[0].Name)

	// Returned wallet should have the correct ID
	a.Equal(resp1.Wallets[0].ID, resp4.Wallets[0].ID)
}

func TestWalletSessionRelease(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Test that `POST /v1/wallet/info` returns a wallet
	req0 := kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp0 := kmdapi.APIV1POSTWalletInfoResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Should return the wallet we created
	a.Equal(resp0.WalletHandle.Wallet.Name, f.WalletName)

	// Test that `POST /v1/wallet/release` succeeds
	req1 := kmdapi.APIV1POSTWalletReleaseRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp1 := kmdapi.APIV1POSTWalletReleaseResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// Test that `POST /v1/wallet/info` no longer works with this token
	req2 := kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp2 := kmdapi.APIV1POSTWalletInfoResponse{}
	err = f.Client.DoV1Request(req2, &resp2)

	// Error response
	a.Error(err)

	// Should not return the wallet we created
	a.NotEqual(resp2.WalletHandle.Wallet.Name, f.WalletName)
}

func TestWalletSessionRenew(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	walletHandleToken := f.SetupWithWallet(t)
	defer f.Shutdown()

	// Get deets about this wallet token
	req0 := kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp0 := kmdapi.APIV1POSTWalletInfoResponse{}
	err := f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Note # seconds until expiration
	expiresSecsInitial := resp0.WalletHandle.ExpiresSeconds

	// Delay for 1.5 seconds
	time.Sleep(2 * time.Second)

	// Confirm expiresSecs has decreased
	req1 := kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp1 := kmdapi.APIV1POSTWalletInfoResponse{}
	err = f.Client.DoV1Request(req1, &resp1)
	a.NoError(err)

	// Should have decreased
	expiresSecsLater := resp1.WalletHandle.ExpiresSeconds
	a.True(expiresSecsLater < expiresSecsInitial)

	// Renew the handle
	req2 := kmdapi.APIV1POSTWalletRenewRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp2 := kmdapi.APIV1POSTWalletRenewResponse{}
	err = f.Client.DoV1Request(req2, &resp2)
	a.NoError(err)

	// Should have increased
	expiresSecsRenewed := resp2.WalletHandle.ExpiresSeconds
	a.True(expiresSecsRenewed > expiresSecsLater)
}

func TestWalletSessionExpiry(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	// Write a config for 1 second session expirations
	cfg := `{"session_lifetime_secs":1,"drivers":{"sqlite":{"scrypt":{"scrypt_n":2},"allow_unsafe_scrypt":true}}}`
	f.SetupWithConfig(t, cfg)
	walletHandleToken, err := f.MakeWalletAndHandleToken()
	defer f.Shutdown()
	a.NoError(err)

	// Get deets about this wallet token to confirm the token works
	req0 := kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp0 := kmdapi.APIV1POSTWalletInfoResponse{}
	err = f.Client.DoV1Request(req0, &resp0)
	a.NoError(err)

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	// Try to use token again, make sure request fails
	req1 := kmdapi.APIV1POSTWalletInfoRequest{
		WalletHandleToken: walletHandleToken,
	}
	resp1 := kmdapi.APIV1POSTWalletInfoResponse{}
	err = f.Client.DoV1Request(req1, &resp1)

	// Token should have expired
	a.Error(err)
}
