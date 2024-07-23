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
	i0 := NewIdentityChallengeScheme()
	i := NewIdentityChallengeScheme(NetIdentityDedupNames(""))
	require.Equal(t, i0, i)
	require.Zero(t, *i)
	chal := i.AttachChallenge(h, "other")
	require.Zero(t, h.Get(IdentityChallengeHeader))
	require.Zero(t, chal)

	j := NewIdentityChallengeScheme(NetIdentityDedupNames("yes"))
	chal = j.AttachChallenge(h, "other")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, chal)
}

// TestIdentityChallengeSchemeVerifyRequestAndAttachResponse will confirm that the scheme
// attaches responses only if dedup name is set and the provided challenge verifies
func TestIdentityChallengeSchemeVerifyRequestAndAttachResponse(t *testing.T) {
	partitiontest.PartitionTest(t)

	i := NewIdentityChallengeScheme(NetIdentityDedupNames("i1"))
	// author a challenge to the other scheme
	h := http.Header{}
	i.AttachChallenge(h, "i2")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))

	// without a dedup name, no response and no error
	h = http.Header{}
	i.AttachChallenge(h, "i2")
	r := http.Header{}
	i2 := NewIdentityChallengeScheme()
	chal, key, err := i2.VerifyRequestAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, chal)
	require.Empty(t, key)
	require.NoError(t, err)

	// if dedup name doesn't match, no response and no error
	h = http.Header{}
	i.AttachChallenge(h, "i2")
	r = http.Header{}
	i2 = NewIdentityChallengeScheme(NetIdentityDedupNames("not i2"))
	chal, key, err = i2.VerifyRequestAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, chal)
	require.Empty(t, key)
	require.NoError(t, err)

	// if the challenge can't be decoded or verified, error
	h = http.Header{}
	h.Add(IdentityChallengeHeader, "garbage")
	r = http.Header{}
	i2 = NewIdentityChallengeScheme(NetIdentityDedupNames("i2"))
	chal, key, err = i2.VerifyRequestAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, chal)
	require.Empty(t, key)
	require.Error(t, err)

	// happy path: response should be attached here
	h = http.Header{}
	i.AttachChallenge(h, "i2")
	r = http.Header{}
	i2 = NewIdentityChallengeScheme(NetIdentityDedupNames("i2"))
	chal, key, err = i2.VerifyRequestAndAttachResponse(r, h)
	require.NotEmpty(t, r.Get(IdentityChallengeHeader))
	require.NotEmpty(t, chal)
	require.NotEmpty(t, key)
	require.NoError(t, err)
}

func TestIdentityChallengeNoErrorWhenNotParticipating(t *testing.T) {
	partitiontest.PartitionTest(t)

	// blank deduplication name will make the scheme a no-op
	iNotParticipate := NewIdentityChallengeScheme()

	// create a request header first
	h := http.Header{}
	i := NewIdentityChallengeScheme(NetIdentityDedupNames("i1"))
	origChal := i.AttachChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)

	// confirm a nil scheme will not return values or error
	c, k, err := iNotParticipate.VerifyRequestAndAttachResponse(http.Header{}, h)
	require.Empty(t, c)
	require.Empty(t, k)
	require.NoError(t, err)

	// create a response
	h2 := http.Header{}
	i2 := NewIdentityChallengeScheme(NetIdentityDedupNames("i2"))
	i2.VerifyRequestAndAttachResponse(h2, h)

	// confirm a nil scheme will not return values or error
	k2, bytes, err := iNotParticipate.VerifyResponse(h2, identityChallengeValue{})
	require.Empty(t, k2)
	require.Empty(t, bytes)
	require.NoError(t, err)

	// add broken payload to a new header and try inspecting it with the empty scheme
	h3 := http.Header{}
	h3.Add(IdentityChallengeHeader, "broken text!")
	c, k, err = iNotParticipate.VerifyRequestAndAttachResponse(http.Header{}, h)
	require.Empty(t, c)
	require.Empty(t, k)
	require.NoError(t, err)
	k2, bytes, err = iNotParticipate.VerifyResponse(h2, identityChallengeValue{})
	require.Empty(t, k2)
	require.Empty(t, bytes)
	require.NoError(t, err)
}

// TestIdentityChallengeSchemeVerifyResponse confirms the scheme will
// attach responses only if dedup name is set and the provided challenge verifies
func TestIdentityChallengeSchemeVerifyResponse(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme(NetIdentityDedupNames("i1"))
	// author a challenge to ourselves
	origChal := i.AttachChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)
	r := http.Header{}

	respChal, key, err := i.VerifyRequestAndAttachResponse(r, h)
	require.NotEmpty(t, r.Get(IdentityChallengeHeader))
	require.NotEmpty(t, respChal)
	require.NotEmpty(t, key)
	require.NoError(t, err)

	// respChal2 should match respChal as it is being passed back to the original peer
	// while origChal will be used for verification
	key2, verificationMsg, err := i.VerifyResponse(r, origChal)
	require.NotEmpty(t, verificationMsg)
	require.NoError(t, err)
	// because we sent this to ourselves, we can confirm the keys match
	require.Equal(t, key, key2)
}

// TestIdentityChallengeSchemeBadSignature tests that the  scheme will
// fail to verify and attach if the challenge is incorrectly signed
func TestIdentityChallengeSchemeBadSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme(NetIdentityDedupNames("i1"))
	// Copy the logic of attaching the header and signing so we can sign it wrong
	c := identityChallengeSigned{
		Msg: identityChallenge{
			Key:           i.identityKeys.PublicKey(),
			Challenge:     newIdentityChallengeValue(),
			PublicAddress: []byte("i1"),
		}}
	c.Signature = i.identityKeys.SignBytes([]byte("WRONG BYTES SIGNED"))
	enc := protocol.Encode(&c)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	h.Add(IdentityChallengeHeader, b64enc)

	// observe that VerifyRequestAndAttachResponse returns error on bad signature
	r := http.Header{}
	respChal, key, err := i.VerifyRequestAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, respChal)
	require.Empty(t, key)
	require.Error(t, err)
}

// TestIdentityChallengeSchemeBadPayload tests that the  scheme will
// fail to verify if the challenge can't be B64 decoded
func TestIdentityChallengeSchemeBadPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme(NetIdentityDedupNames("i1"))
	h.Add(IdentityChallengeHeader, "NOT VALID BASE 64! :)")

	// observe that VerifyRequestAndAttachResponse won't do anything on bad signature
	r := http.Header{}
	respChal, key, err := i.VerifyRequestAndAttachResponse(r, h)
	require.Empty(t, r.Get(IdentityChallengeHeader))
	require.Empty(t, respChal)
	require.Empty(t, key)
	require.Error(t, err)
}

// TestIdentityChallengeSchemeBadResponseSignature tests that the  scheme will
// fail to verify if the challenge response is incorrectly signed
func TestIdentityChallengeSchemeBadResponseSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme(NetIdentityDedupNames("i1"))
	// author a challenge to ourselves
	origChal := i.AttachChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)

	// use the code to sign and encode responses so we can sign incorrectly
	r := http.Header{}
	resp := identityChallengeResponseSigned{
		Msg: identityChallengeResponse{
			Key:               i.identityKeys.PublicKey(),
			Challenge:         origChal,
			ResponseChallenge: newIdentityChallengeValue(),
		}}
	resp.Signature = i.identityKeys.SignBytes([]byte("BAD BYTES FOR SIGNING"))
	enc := protocol.Encode(&resp)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	r.Add(IdentityChallengeHeader, b64enc)

	key2, verificationMsg, err := i.VerifyResponse(r, origChal)
	require.Empty(t, key2)
	require.Empty(t, verificationMsg)
	require.Error(t, err)
}

// TestIdentityChallengeSchemeBadResponsePayload tests that the  scheme will
// fail to verify if the challenge response can't be B64 decoded
func TestIdentityChallengeSchemeBadResponsePayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme(NetIdentityDedupNames("i1"))
	// author a challenge to ourselves
	origChal := i.AttachChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)

	// generate a bad payload that should not decode
	r := http.Header{}
	r.Add(IdentityChallengeHeader, "BAD B64 ENCODING :)")

	key2, verificationMsg, err := i.VerifyResponse(r, origChal)
	require.Empty(t, key2)
	require.Empty(t, verificationMsg)
	require.Error(t, err)
}

// TestIdentityChallengeSchemeWrongChallenge the scheme will
// return "0" if the challenge does not match upon return
func TestIdentityChallengeSchemeWrongChallenge(t *testing.T) {
	partitiontest.PartitionTest(t)

	h := http.Header{}
	i := NewIdentityChallengeScheme(NetIdentityDedupNames("i1"))
	// author a challenge to ourselves
	origChal := i.AttachChallenge(h, "i1")
	require.NotEmpty(t, h.Get(IdentityChallengeHeader))
	require.NotEmpty(t, origChal)

	r := http.Header{}
	respChal, key, err := i.VerifyRequestAndAttachResponse(r, h)
	require.NotEmpty(t, r.Get(IdentityChallengeHeader))
	require.NotEmpty(t, respChal)
	require.NotEmpty(t, key)
	require.NoError(t, err)

	// Attempt to verify against the wrong challenge
	key2, verificationMsg, err := i.VerifyResponse(r, newIdentityChallengeValue())
	require.Empty(t, key2)
	require.Empty(t, verificationMsg)
	require.Error(t, err)
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

// Just tests that if a peer is already verified, it just returns OutgoingMessage{}
func TestIdentityTrackerHandlerGuard(t *testing.T) {
	partitiontest.PartitionTest(t)
	p := wsPeer{}
	p.identityVerified.Store(1)
	msg := IncomingMessage{
		Sender: &p,
		Net:    &WebsocketNetwork{},
	}
	require.Equal(t, OutgoingMessage{}, identityVerificationHandler(msg))
}

// TestNewIdentityChallengeScheme ensures NewIdentityChallengeScheme returns
// a correct identityChallengePublicKeyScheme for the following inputs:
// DedupNames(a, b) vs DedupNames(a), DedupNames(b)
// Empty vs non-empty PeerID, PublicAddress
// Empty vs non-empty Signer
func TestNewIdentityChallengeScheme(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	s1 := NewIdentityChallengeScheme()
	s2 := NewIdentityChallengeScheme(NetIdentityDedupNames(""))
	s3 := NewIdentityChallengeScheme(NetIdentityDedupNames("", ""))
	s4 := NewIdentityChallengeScheme(NetIdentityDedupNames(""), NetIdentityDedupNames(""))
	require.Equal(t, s1, s2)
	require.Equal(t, s2, s3)
	require.Equal(t, s3, s4)
	require.Zero(t, *s1)

	s1 = NewIdentityChallengeScheme(NetIdentityDedupNames("a", "a"))
	s2 = NewIdentityChallengeScheme(NetIdentityDedupNames("a"), NetIdentityDedupNames("a"))
	require.Equal(t, s1.dedupNames, s2.dedupNames)
	require.Len(t, s1.dedupNames, 1)
	require.IsType(t, &identityChallengeLegacySigner{}, s1.identityKeys)
	require.IsType(t, &identityChallengeLegacySigner{}, s2.identityKeys)
	require.NotEqual(t, s1.identityKeys, s2.identityKeys)

	s1 = NewIdentityChallengeScheme(NetIdentityDedupNames("a", "b"))
	s2 = NewIdentityChallengeScheme(NetIdentityDedupNames("a"), NetIdentityDedupNames("b"))
	require.Equal(t, s1.dedupNames, s2.dedupNames)
	require.Len(t, s1.dedupNames, 2)
	require.IsType(t, &identityChallengeLegacySigner{}, s1.identityKeys)
	require.IsType(t, &identityChallengeLegacySigner{}, s2.identityKeys)
	require.NotEqual(t, s1.identityKeys, s2.identityKeys)

	s1 = NewIdentityChallengeScheme(NetIdentityDedupNames("", "a"))
	s2 = NewIdentityChallengeScheme(NetIdentityDedupNames("a"), NetIdentityDedupNames(""))
	s3 = NewIdentityChallengeScheme(NetIdentityDedupNames("a", ""))
	s4 = NewIdentityChallengeScheme(NetIdentityDedupNames(""), NetIdentityDedupNames("a"))
	require.Equal(t, s1.dedupNames, s2.dedupNames)
	require.Equal(t, s2.dedupNames, s3.dedupNames)
	require.Equal(t, s3.dedupNames, s4.dedupNames)
	require.Len(t, s1.dedupNames, 1)
	require.IsType(t, &identityChallengeLegacySigner{}, s1.identityKeys)
	require.IsType(t, &identityChallengeLegacySigner{}, s2.identityKeys)
	require.NotEqual(t, s1.identityKeys, s2.identityKeys)

	s1 = NewIdentityChallengeScheme(NetIdentityDedupNames("a"), NetIdentitySigner(&identityChallengeLegacySigner{}))
	require.Len(t, s1.dedupNames, 1)
	require.IsType(t, &identityChallengeLegacySigner{}, s1.identityKeys)

	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	signer := &identityChallengeLegacySigner{keys: crypto.GenerateSignatureSecrets(seed)}
	s1 = NewIdentityChallengeScheme(NetIdentityDedupNames("a"), NetIdentitySigner(signer))
	require.Len(t, s1.dedupNames, 1)
	require.IsType(t, &identityChallengeLegacySigner{}, s1.identityKeys)
	require.Equal(t, signer, s1.identityKeys)

	s1 = NewIdentityChallengeScheme(NetIdentityDedupNames(""), NetIdentitySigner(signer))
	require.Empty(t, s1)
	s1 = NewIdentityChallengeScheme(NetIdentitySigner(signer))
	require.Empty(t, s1)
}
