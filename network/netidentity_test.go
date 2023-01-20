// Copyright (C) 2019-2023 Algorand, Inc.
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

// Copyright (C) 2019-2022 Algorand, Inc.
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

package network

import (
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestIdentityChallengeEncodeDecodeVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)
	k := (crypto.PublicKey)(secrets.SignatureVerifier)
	addr := "test address"

	c, header := NewIdentityChallengeAndHeader(secrets, addr)
	require.NotEmpty(t, header)
	require.NotEmpty(t, c)

	// confirm the same challenge that was returned and included in the struct
	idChal := IdentityChallengeFromB64(header)
	require.Equal(t, addr, idChal.Address)
	require.Equal(t, k, idChal.Key)
	require.Equal(t, c, idChal.Challenge)
	require.NotEmpty(t, idChal.Signature)
	require.True(t, idChal.Verify())

	// if the signature does not match the data, it should not Verify
	idChal.Address = "changed bytes"
	require.False(t, idChal.Verify())
}

func TestIdentityChallengeFailedDecode(t *testing.T) {
	partitiontest.PartitionTest(t)
	idChal := IdentityChallengeFromB64("NOT VALID BASE-64!")
	require.Equal(t, identityChallenge{}, idChal)
	// confirm the empty returned challenge can't Verify
	require.False(t, idChal.Verify())
}

func TestIdentityChallengeResponseEncodeDecodeVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)
	respSecrets := crypto.GenerateSignatureSecrets(seed)
	k := (crypto.PublicKey)(respSecrets.SignatureVerifier)
	addr := "test address"

	c, header := NewIdentityChallengeAndHeader(secrets, addr)
	idChal := IdentityChallengeFromB64(header)

	rc, respHeader := NewIdentityResponseChallengeAndHeader(respSecrets, idChal)
	require.NotEmpty(t, rc)
	require.NotEmpty(t, respHeader)
	idChalResp := IdentityChallengeResponseFromB64(respHeader)
	require.Equal(t, k, idChalResp.Key)
	require.Equal(t, c, idChalResp.Challenge)
	require.Equal(t, rc, idChalResp.ResponseChallenge)
	require.NotEmpty(t, idChalResp.Signature)
	require.True(t, idChalResp.Verify())

	// make some bogus challenge to invalidate the struct and confirm it does not verify
	wrongChallenge, _ := NewIdentityChallengeAndHeader(secrets, addr)
	idChalResp.ResponseChallenge = wrongChallenge
	require.False(t, idChalResp.Verify())
}

func TestIdentityChallengeResponseFailedDecode(t *testing.T) {
	partitiontest.PartitionTest(t)
	idChalResp := IdentityChallengeResponseFromB64("NOT VALID BASE-64!")
	require.Equal(t, identityChallengeResponse{}, idChalResp)
	// confirm the empty returned challenge can't Verify
	require.False(t, idChalResp.Verify())
}

func TestIdentityVerificationHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	chalSecrets := crypto.GenerateSignatureSecrets(seed)
	chal := [32]byte{}
	crypto.RandBytes(chal[:])
	sig := chalSecrets.SignBytes(chal[:])
	p := wsPeer{
		identity:          (crypto.PublicKey)(chalSecrets.SignatureVerifier),
		identityChallenge: chal,
		identityVerified:  0,
	}

	i := IncomingMessage{
		Sender: &p,
		Tag:    protocol.NetIDVerificationTag,
		Data:   sig[:],
	}
	identityVerificationHandler(i)
	require.Equal(t, uint32(1), p.identityVerified)
}

func TestIdentityVerificationHandlerBadSignature(t *testing.T) {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	chalSecrets := crypto.GenerateSignatureSecrets(seed)
	chal := [32]byte{}
	crypto.RandBytes(chal[:])
	sig := chalSecrets.SignBytes(chal[:])
	// Reset the challenge to force the signature to be wrong
	crypto.RandBytes(chal[:])
	p := wsPeer{
		identity:          (crypto.PublicKey)(chalSecrets.SignatureVerifier),
		identityChallenge: chal,
		identityVerified:  0,
	}

	i := IncomingMessage{
		Sender: &p,
		Tag:    protocol.NetIDVerificationTag,
		Data:   sig[:],
	}
	identityVerificationHandler(i)
	require.Equal(t, uint32(0), p.identityVerified)
}

func TestNewIdentityTracker(t *testing.T) {
	partitiontest.PartitionTest(t)

	tracker := NewIdentityTracker()
	require.Empty(t, tracker.peersByID)
}

func TestIdentityTrackerRemoveIdentity(t *testing.T) {
	partitiontest.PartitionTest(t)

	tracker := NewIdentityTracker()
	id := crypto.PublicKey{}
	p := wsPeer{identity: id}

	// Ensure the first attempt to insert populates the map
	_, exists := tracker.peersByID[p.identity]
	require.False(t, exists)
	require.True(t, tracker.setIdentity(&p))
	_, exists = tracker.peersByID[p.identity]
	require.True(t, exists)

	tracker.removeIdentity(&p)
	_, exists = tracker.peersByID[p.identity]
	require.False(t, exists)
}

func TestIdentityTrackerSetIdentity(t *testing.T) {
	partitiontest.PartitionTest(t)

	tracker := NewIdentityTracker()
	id := crypto.PublicKey{}
	p := wsPeer{identity: id}

	// Ensure the first attempt to insert populates the map
	_, exists := tracker.peersByID[p.identity]
	require.False(t, exists)
	require.True(t, tracker.setIdentity(&p))
	_, exists = tracker.peersByID[p.identity]
	require.True(t, exists)

	// Ensure the next attempt to insert also returns true
	require.True(t, tracker.setIdentity(&p))

	// Ensure a different peer cannot take the map entry
	otherP := wsPeer{identity: id}
	require.False(t, tracker.setIdentity(&otherP))

	// Ensure the entry in the map wasn't changed
	require.Equal(t, tracker.peersByID[p.identity], &p)
}
