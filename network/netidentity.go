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
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

type identityChallengeBytes [32]byte

func newIdentityChallengeBytes() identityChallengeBytes {
	var ret identityChallengeBytes
	crypto.RandBytes(ret[:])
	return ret
}

type identityChallengeScheme struct {
	dedupName    string
	identityKeys *crypto.SignatureSecrets
}

// NewIdentityChallengeScheme will create a default ID Scheme (identityChallengeScheme)
func NewIdentityChallengeScheme(dn string) *identityChallengeScheme {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])

	return &identityChallengeScheme{
		dedupName:    dn,
		identityKeys: crypto.GenerateSignatureSecrets(seed),
	}
}

// AttachNewIdentityChallenge will generate a new identity challenge
// and will encode and attach the challenge as a header.
// returns the identityChallengeBytes used for this challenge so the network can confirm it later
// or returns an empty challenge if dedupName is not set
func (i identityChallengeScheme) AttachNewIdentityChallenge(attach http.Header, addr string) identityChallengeBytes {
	if i.dedupName == "" {
		return identityChallengeBytes{}
	}
	c := identityChallenge{
		Key:       i.identityKeys.SignatureVerifier,
		Challenge: newIdentityChallengeBytes(),
		Address:   addr,
	}

	attach.Add(IdentityChallengeHeader, c.signAndEncodeB64(i.identityKeys))
	return c.Challenge
}

// VerifyAndAttachResponse  headers for an Identity Challenge, and verifies:
// * the provided challenge bytes matches the one encoded in the header
// * the identity challenge verifies against the included key
// * the "Address" field matches what this scheme expects
// once verified, it will attach the header to the "attach" header
// and will return the challenge and identity of the peer for recording
// or returns empty values if the header did not end up getting set
func (i identityChallengeScheme) VerifyAndAttachResponse(attach http.Header, h http.Header) (identityChallengeBytes, crypto.PublicKey) {
	if i.dedupName == "" {
		return identityChallengeBytes{}, crypto.PublicKey{}
	}
	// decode the header to an identityChallenge
	msg, err := base64.StdEncoding.DecodeString(h.Get(IdentityChallengeHeader))
	if err != nil {
		return identityChallengeBytes{}, crypto.PublicKey{}
	}
	idChal := identityChallenge{}
	err = protocol.DecodeReflect(msg, &idChal)
	if err != nil {
		return identityChallengeBytes{}, crypto.PublicKey{}
	}
	// confirm the Address matches, and the challenge verifies
	if idChal.Address != i.dedupName || !idChal.Verify() {
		return identityChallengeBytes{}, crypto.PublicKey{}
	}

	// make the response object, encode it and attach it to the header
	r := identityChallengeResponse{
		Key:               i.identityKeys.SignatureVerifier,
		Challenge:         idChal.Challenge,
		ResponseChallenge: newIdentityChallengeBytes(),
	}
	attach.Add(IdentityChallengeHeader, r.signAndEncodeB64(i.identityKeys))
	return r.ResponseChallenge, idChal.Key
}

// VerifyResponse will decode the identity challenge header and confirm it self-verifies,
// and that the provided challenge matches the encoded one
// returns the response challenge and claimed key of the peer, and if it can be verified
func (i identityChallengeScheme) VerifyResponse(h http.Header, c identityChallengeBytes) (identityChallengeBytes, crypto.PublicKey, uint32) {
	msg, err := base64.StdEncoding.DecodeString(h.Get(IdentityChallengeHeader))
	if err != nil {
		return identityChallengeBytes{}, crypto.PublicKey{}, 0
	}
	resp := identityChallengeResponse{}
	err = protocol.DecodeReflect(msg, &resp)
	if err != nil {
		return identityChallengeBytes{}, crypto.PublicKey{}, 0
	}
	if resp.Challenge == c && resp.Verify() {
		return resp.ResponseChallenge, resp.Key, 1
	}
	return identityChallengeBytes{}, crypto.PublicKey{}, 0
}

// SendIdentityChallengeVerification sends the 3rd (final) message for signature handshake between two peers.
// it simply sends across a signature of a challenge which the potential peer has given it to sign.
// at this stage in the peering process, the peer hasn't had an opportunity to verify our supposed identity
func (i *identityChallengeScheme) SendIdentityChallengeVerification(wp *wsPeer, c identityChallengeBytes) error {
	sig := i.identityKeys.SignBytes(c[:])
	mbytes := append([]byte(protocol.NetIDVerificationTag), sig[:]...)
	sent := wp.writeNonBlock(context.Background(), mbytes, true, crypto.Digest{}, time.Now())
	if !sent {
		return fmt.Errorf("could not send identity challenge verification")
	}
	return nil
}

type identityChallenge struct {
	Key       crypto.PublicKey       `codec:"pk"`
	Challenge identityChallengeBytes `codec:"c"`
	Address   string                 `codec:"a"`
	Signature crypto.Signature       `codec:"s"`
}

type identityChallengeResponse struct {
	Key               crypto.PublicKey `codec:"pk"`
	Challenge         [32]byte         `codec:"c"`
	ResponseChallenge [32]byte         `codec:"rc"`
	Signature         crypto.Signature `codec:"s"`
}

func (i *identityChallenge) signAndEncodeB64(s *crypto.SignatureSecrets) string {
	i.Signature = s.SignBytes(i.signableBytes())
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	return b64enc
}

func (i identityChallenge) signableBytes() []byte {
	return bytes.Join([][]byte{
		[]byte("IC"),
		i.Challenge[:],
		i.Key[:],
		[]byte(i.Address),
	},
		[]byte(":"))
}

// Verify checks that the signature included in the identityChallenge was indeed created by the included Key
func (i identityChallenge) Verify() bool {
	return i.Key.VerifyBytes(i.signableBytes(), i.Signature)
}

func (i *identityChallengeResponse) signAndEncodeB64(s *crypto.SignatureSecrets) string {
	i.Signature = s.SignBytes(i.signableBytes())
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	return b64enc
}

func (i identityChallengeResponse) signableBytes() []byte {
	return bytes.Join([][]byte{
		[]byte("ICR"),
		i.Challenge[:],
		i.ResponseChallenge[:],
		i.Key[:],
	},
		[]byte(":"))
}

// Verify checks that the signature included in the identityChallengeResponse was indeed created by the included Key
func (i identityChallengeResponse) Verify() bool {
	return i.Key.VerifyBytes(i.signableBytes(), i.Signature)
}

// identityVerificationHandler receives a signature over websocket, and confirms it matches the
// sender's claimed identity and the challenge that was assigned to it. If the identity is available,
// the peer is loaded into the identity tracker. Otherwise, we ask the network to disconnect the peer
func identityVerificationHandler(message IncomingMessage) OutgoingMessage {
	peer := message.Sender.(*wsPeer)
	// avoid doing work (crypto and potentially taking a lock) if the peer is already verified
	if atomic.LoadUint32(&peer.identityVerified) == 1 {
		return OutgoingMessage{}
	}
	sig := crypto.Signature{}
	copy(sig[:], message.Data[:64])
	if !peer.identity.VerifyBytes(peer.identityChallenge[:], sig) {
		return OutgoingMessage{}
	}
	atomic.StoreUint32(&peer.identityVerified, 1)
	// if the identity could not be claimed by this peer, it means the identity is in use
	peer.net.peersLock.Lock()
	ok := peer.net.identityTracker.setIdentity(peer)
	peer.net.peersLock.Unlock()
	if !ok {
		networkPeerDisconnectDupeIdentity.Inc(nil)
		peer.net.Disconnect(peer)
	}
	return OutgoingMessage{}
}

var identityHandlers = []TaggedMessageHandler{
	{protocol.NetIDVerificationTag, HandlerFunc(identityVerificationHandler)},
}

// identityTracker is used by wsNetwork to manage peer identities for connection deduplication
type identityTracker interface {
	removeIdentity(p *wsPeer)
	setIdentity(p *wsPeer) bool
}

// publicKeyIdentTracker implements identityTracker by
// mapping from PublicKeys exchanged in identity challenges to a peer
// this structure is not thread-safe; it is protected by wn.peersLock.
type publicKeyIdentTracker struct {
	peersByID map[crypto.PublicKey]*wsPeer
}

// NewIdentityTracker returns a new publicKeyIdentTracker
func NewIdentityTracker() *publicKeyIdentTracker {
	return &publicKeyIdentTracker{
		peersByID: make(map[crypto.PublicKey]*wsPeer),
	}
}

// setIdentity attempts to store a peer at its identity.
// returns false if it was unable to load the peer into the given identity
// or true otherwise (if the peer was already there, or if it was added)
func (t *publicKeyIdentTracker) setIdentity(p *wsPeer) bool {
	existingPeer, exists := t.peersByID[p.identity]
	if !exists {
		// the identity is not occupied, so set it and return true
		t.peersByID[p.identity] = p
		return true
	}
	// the identity is occupied, so return false if it is occupied by some *other* peer
	// or true if it is occupied by this peer
	return existingPeer == p
}

// removeIdentity removes the entry in the peersByID map if it exists
// and is occupied by the given peer
func (t *publicKeyIdentTracker) removeIdentity(p *wsPeer) {
	if t.peersByID[p.identity] == p {
		delete(t.peersByID, p.identity)
	}
}
