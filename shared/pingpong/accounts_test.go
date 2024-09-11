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

package pingpong

import (
	"encoding/binary"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
)

func makeKeyFromSeed(i uint64) *crypto.SignatureSecrets {
	var seed crypto.Seed
	binary.LittleEndian.PutUint64(seed[:], i)
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func TestDeterministicAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	initCfg := PpConfig{
		NumPartAccounts:        20,
		DeterministicKeys:      true,
		GeneratedAccountsCount: 100,
	}

	// created expected set of keys in a similar way as netgoal generate --deterministic
	expectedPubKeys := make(map[crypto.PublicKey]*crypto.SignatureSecrets)
	for i := 0; i < int(initCfg.GeneratedAccountsCount); i++ {
		key := makeKeyFromSeed(uint64(i))
		expectedPubKeys[key.SignatureVerifier] = key
	}
	assert.Len(t, expectedPubKeys, int(initCfg.GeneratedAccountsCount))

	// call pingpong acct generator and assert its separately-generated secrets are equal
	accountSecrets := deterministicAccounts(initCfg)
	cnt := 0
	for secret := range accountSecrets {
		t.Log("Got address", basics.Address(secret.SignatureVerifier))
		assert.Contains(t, expectedPubKeys, secret.SignatureVerifier)
		assert.Equal(t, *expectedPubKeys[secret.SignatureVerifier], *secret)
		cnt++
	}
	assert.Equal(t, int(initCfg.NumPartAccounts), cnt)
}
