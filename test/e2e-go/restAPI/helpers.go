// Copyright (C) 2019-2024 Algorand, Inc.
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

package restapi

import (
	"errors"
	"math/rand"
	"testing"
	"time"

	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

// helper generates a random Uppercase Alphabetic ASCII char
func randomUpperAlphaAsByte() byte {
	return byte(65 + rand.Intn(25))
}

// RandomString helper generates a random string
// snippet credit to many places, one such place is https://medium.com/@kpbird/golang-generate-fixed-size-random-string-dd6dbd5e63c0
func RandomString(len int) string {
	// re-seed the RNG to mitigate randomString collisions across tests
	rand.Seed(time.Now().UnixNano())
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = randomUpperAlphaAsByte()
	}
	return string(bytes)
}

// helper replaces a string's character at index
func replaceAtIndex(in string, r rune, i int) string {
	out := []rune(in)
	out[i] = r
	return string(out)
}

// helper replaces a string's character at index with a random, different uppercase alphabetic ascii char
func mutateStringAtIndex(in string, i int) (out string) {
	out = in
	for out == in {
		out = replaceAtIndex(in, rune(randomUpperAlphaAsByte()), i)
	}
	return out
}

// GetMaxBalAddr returns the address with the highest balance
func GetMaxBalAddr(t *testing.T, testClient libgoal.Client, addresses []string) (someBal uint64, someAddress string) {
	a := require.New(fixtures.SynchronizedTest(t))
	someBal = 0
	for _, addr := range addresses {
		bal, err := testClient.GetBalance(addr)
		a.NoError(err)
		if bal > someBal {
			someAddress = addr
			someBal = bal
		}
	}
	return
}

// GetDestAddr returns an address that is not someAddress
func GetDestAddr(t *testing.T, testClient libgoal.Client, addresses []string, someAddress string, wh []byte) (toAddress string) {
	a := require.New(fixtures.SynchronizedTest(t))
	if len(addresses) > 1 {
		for _, addr := range addresses {
			if addr != someAddress {
				toAddress = addr
				return
			}
		}
	}
	var err error
	toAddress, err = testClient.GenerateAddress(wh)
	a.NoError(err)
	return
}

// WaitForRoundOne waits for round 1
func WaitForRoundOne(t *testing.T, testClient libgoal.Client) {
	a := require.New(fixtures.SynchronizedTest(t))
	errchan := make(chan error)
	quit := make(chan struct{})
	go func() {
		_, xe := testClient.WaitForRound(1)
		select {
		case errchan <- xe:
		case <-quit:
		}
	}()
	select {
	case err := <-errchan:
		a.NoError(err)
	case <-time.After(1 * time.Minute): // Wait 1 minute (same as WaitForRound)
		close(quit)
		t.Fatalf("%s: timeout waiting for round 1", t.Name())
	}
}

var errWaitForTransactionTimeout = errors.New("wait for transaction timed out")

// WaitForTransaction waits for a transaction to be confirmed
func WaitForTransaction(t *testing.T, testClient libgoal.Client, txID string, timeout time.Duration) (tx v2.PreEncodedTxInfo, err error) {
	a := require.New(fixtures.SynchronizedTest(t))
	rnd, err := testClient.Status()
	a.NoError(err)
	if rnd.LastRound == 0 {
		t.Fatal("it is currently round 0 but we need to wait for a transaction that might happen this round but we'll never know if that happens because ConfirmedRound==0 is indestinguishable from not having happened")
	}
	timeoutTime := time.Now().Add(timeout)
	for {
		tx, err = testClient.ParsedPendingTransaction(txID)
		if err == nil {
			a.NotEmpty(tx)
			a.Empty(tx.PoolError)
			if tx.ConfirmedRound != nil && *tx.ConfirmedRound > 0 {
				return
			}
		}
		if time.Now().After(timeoutTime) {
			err = errWaitForTransactionTimeout
			return
		}
		time.Sleep(time.Second)
	}
}
