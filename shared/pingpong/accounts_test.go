package pingpong

import (
	"encoding/binary"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/stretchr/testify/assert"
)

func makeKey(i uint64) *crypto.SignatureSecrets {
	var seed crypto.Seed
	binary.LittleEndian.PutUint64(seed[:], i)
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func TestDeterministicAccounts(t *testing.T) {
	initCfg := PpConfig{
		NumPartAccounts:        20,
		DeterministicKeys:      true,
		GeneratedAccountsCount: 100,
	}

	// created expected set of keys similar like how netgoal does
	expectedPubKeys := make(map[crypto.PublicKey]*crypto.SignatureSecrets)
	for i := 0; i < int(initCfg.GeneratedAccountsCount); i++ {
		key := makeKey(uint64(i))
		expectedPubKeys[key.SignatureVerifier] = key
	}
	assert.Len(t, expectedPubKeys, int(initCfg.GeneratedAccountsCount))

	// call pingpong generator and assert separate-generated accounts are equal
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
