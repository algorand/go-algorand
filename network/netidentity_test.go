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
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// if the scheme has a dedup name, attach to headers. otherwise, don't
func TestIdentityChallengeSchemeAttachIfEnabled(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme("")
	chal := i.AttachNewIdentityChallenge(h, "other")
	require.Empty(t, h.Get(IdentityChallengeHeader))
	require.Empty(t, chal)

	j := NewIdentityChallengeScheme("yes")
	chal = j.AttachNewIdentityChallenge(h, "other")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, chal)
}

// TestIdentityChallengeSchemeVerifyAndAttachResponce will confirm that the scheme
// attaches responses only if dedup name is set and the provided challenge verifies
func TestIdentityChallengeSchemeVerifyAndAttachResponce(t *testing.T) {
	partitiontest.PartitionTest(t)

	i := NewIdentityChallengeScheme("i1")
	// author a challenge to the other scheme
	h := http.Header{}
	i.AttachNewIdentityChallenge(h, "i2")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))

	// without a dedup name, no response
	h = http.Header{}
	i.AttachNewIdentityChallenge(h, "i2")
	r := http.Header{}
	i2 := NewIdentityChallengeScheme("")
	chal, key := i2.VerifyAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, chal)
	require.Empty(t, key)

	// if dedup name doesn't match, no response
	h = http.Header{}
	i.AttachNewIdentityChallenge(h, "i2")
	r = http.Header{}
	i2 = NewIdentityChallengeScheme("not i2")
	chal, key = i2.VerifyAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, chal)
	require.Empty(t, key)

	// if the challenge can't be decoded or verified, no response
	h = http.Header{}
	h.Add("garbage", IdentityChallengeHeader)
	r = http.Header{}
	i2 = NewIdentityChallengeScheme("i2")
	chal, key = i2.VerifyAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, chal)
	require.Empty(t, key)

	// happy path: response should be attached here
	h = http.Header{}
	i.AttachNewIdentityChallenge(h, "i2")
	r = http.Header{}
	i2 = NewIdentityChallengeScheme("i2")
	chal, key = i2.VerifyAndAttachResponse(r, h)
	require.NotEmpty(t, r.Get(IdentityChallengeHeader))
	require.NotEmpty(t, chal)
	require.NotEmpty(t, key)
}

// TestIdentityChallengeSchemeVerifyResponse confirms the scheme will
// attach responses only if dedup name is set and the provided challenge verifies
func TestIdentityChallengeSchemeVerifyResponse(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme("i1")
	// author a challenge to ourselves
	origChal := i.AttachNewIdentityChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)
	r := http.Header{}

	respChal, key := i.VerifyAndAttachResponse(r, h)
	require.NotEmpty(t, r.Get(IdentityChallengeHeader))
	require.NotEmpty(t, respChal)
	require.NotEmpty(t, key)

	// respChal2 should match respChal as it is being passed back to the original peer
	// while origChal will be used for verification
	respChal2, key2, ok := i.VerifyResponse(r, origChal)
	require.Equal(t, respChal, respChal2)
	require.Equal(t, uint32(1), ok)
	// because we sent this to ourselves, we can confirm the keys match
	require.Equal(t, key, key2)
}

// TestIdentityChallengeSchemeBadSignature tests that the  scheme will
// fail to verify and attach if the challenge is incorrectly signed
func TestIdentityChallengeSchemeBadSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme("i1")
	// Copy the logic of attaching the header and signing so we can sign it wrong
	c := identityChallenge{
		Key:       i.identityKeys.SignatureVerifier,
		Challenge: newIdentityChallengeValue(),
		Address:   []byte("i1"),
	}
	c.Signature = i.identityKeys.SignBytes([]byte("WRONG BYTES SIGNED"))
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	h.Add(IdentityChallengeHeader, b64enc)

	// observe that VerifyAndAttachResponse won't do anything on bad signature
	r := http.Header{}
	respChal, key := i.VerifyAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, respChal)
	require.Empty(t, key)
}

// TestIdentityChallengeSchemeBadPayload tests that the  scheme will
// fail to verify if the challenge can't be B64 decoded
func TestIdentityChallengeSchemeBadPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme("i1")
	h.Add(IdentityChallengeHeader, "NOT VALID BASE 64! :)")

	// observe that VerifyAndAttachResponse won't do anything on bad signature
	r := http.Header{}
	respChal, key := i.VerifyAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, respChal)
	require.Empty(t, key)
}

// TestIdentityChallengeSchemeBadResponseSignature tests that the  scheme will
// fail to verify if the challenge response is incorrectly signed
func TestIdentityChallengeSchemeBadResponseSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme("i1")
	// author a challenge to ourselves
	origChal := i.AttachNewIdentityChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)

	// use the code to sign and encode responses so we can sign incorrectly
	r := http.Header{}
	resp := identityChallengeResponse{
		Key:               i.identityKeys.SignatureVerifier,
		Challenge:         origChal,
		ResponseChallenge: newIdentityChallengeValue(),
	}
	resp.Signature = i.identityKeys.SignBytes([]byte("BAD BYTES FOR SIGNING"))
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	r.Add(IdentityChallengeHeader, b64enc)

	respChal2, key2, ok := i.VerifyResponse(r, origChal)
	require.Empty(t, respChal2)
	require.Empty(t, key2)
	require.Equal(t, uint32(0), ok)
}

// TestIdentityChallengeSchemeBadResponsePayload tests that the  scheme will
// fail to verify if the challenge response can't be B64 decoded
func TestIdentityChallengeSchemeBadResponsePayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme("i1")
	// author a challenge to ourselves
	origChal := i.AttachNewIdentityChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)

	// generate a bad payload that should not decode
	r := http.Header{}
	r.Add(IdentityChallengeHeader, "BAD B64 ENCODING :)")

	respChal2, key2, ok := i.VerifyResponse(r, origChal)
	require.Empty(t, respChal2)
	require.Empty(t, key2)
	require.Equal(t, uint32(0), ok)
}

// TestIdentityChallengeSchemeWrongChallenge the scheme will
// return "0" if the challenge does not match upon return
func TestIdentityChallengeSchemeWrongChallenge(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme("i1")
	// author a challenge to ourselves
	origChal := i.AttachNewIdentityChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)

	r := http.Header{}
	respChal, key := i.VerifyAndAttachResponse(r, h)
	require.NotEmpty(t, r.Get(IdentityChallengeHeader))
	require.NotEmpty(t, respChal)
	require.NotEmpty(t, key)

	// Attempt to verify against the wrong challenge
	respChal2, key2, ok := i.VerifyResponse(r, newIdentityChallengeValue())
	require.Empty(t, respChal2)
	require.Equal(t, uint32(0), ok)
	require.Empty(t, key2)
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

	id2 := crypto.PublicKey{}
	p2 := wsPeer{identity: id2}

	// Ensure the first attempt to insert populates the map
	_, exists := tracker.peersByID[p.identity]
	require.False(t, exists)
	require.True(t, tracker.setIdentity(&p))
	_, exists = tracker.peersByID[p.identity]
	require.True(t, exists)

	// check that removing a peer who does not exist in the map (but whos identity does)
	// not not result in the wrong peer being removed
	tracker.removeIdentity(&p2)
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
