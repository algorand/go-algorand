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

package algod

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func BenchmarkSendPayment(b *testing.B) {
	var fixture fixtures.LibGoalFixture
	fixture.SetupNoStart(b, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	fixture.Start()
	defer fixture.Shutdown()
	binDir := fixture.GetBinDir()

	a := require.New(fixtures.SynchronizedTest(b))

	c, err := libgoal.MakeClientWithBinDir(binDir, fixture.PrimaryDataDir(), fixture.PrimaryDataDir(), libgoal.FullClient)
	a.NoError(err)

	wallet, err := c.GetUnencryptedWalletHandle()
	a.NoError(err)

	addrs, err := c.ListAddresses(wallet)
	a.NoError(err)
	require.True(b, len(addrs) > 0)
	addr := addrs[0]

	b.Run("getwallet", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = c.GetUnencryptedWalletHandle()
			a.NoError(err)
		}
	})

	var tx transactions.Transaction
	b.Run("construct", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var nonce [8]byte
			crypto.RandBytes(nonce[:])
			tx, err = c.ConstructPayment(addr, addr, 1, 1, nonce[:], "", [32]byte{}, 0, 0)
			a.NoError(err)
		}
	})

	b.Run("signtxn", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = c.SignTransactionWithWallet(wallet, nil, tx)
			a.NoError(err)
		}
	})

	b.Run("sendpayment", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var nonce [8]byte
			crypto.RandBytes(nonce[:])
			_, err := c.SendPaymentFromWallet(wallet, nil, addr, addr, 1, 1, nonce[:], "", 0, 0)
			a.NoError(err)
		}
	})
}
