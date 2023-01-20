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
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"
)

type identityChallenge struct {
	Key       crypto.PublicKey `codec:"pk"`
	Challenge [32]byte         `codec:"c"`
	Address   string           `codec:"a"`
	Signature crypto.Signature `codec:"s"`
}

type identityChallengeResponse struct {
	Key               crypto.PublicKey `codec:"pk"`
	Challenge         [32]byte         `codec:"c"`
	ResponseChallenge [32]byte         `codec:"rc"`
	Signature         crypto.Signature `codec:"s"`
}

// NewIdentityChallengeAndHeader will create an identityChallenge, and will return the underlying 32 byte challenge itself,
// and the Signed and B64 encoded header of the challenge object
func NewIdentityChallengeAndHeader(keys *crypto.SignatureSecrets, addr string) ([32]byte, string) {
	c := identityChallenge{
		Key:       keys.SignatureVerifier,
		Challenge: [32]byte{},
		Address:   addr,
	}
	crypto.RandBytes(c.Challenge[:])
	return c.Challenge, c.signAndEncodeB64(keys)
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

// IdentityChallengeFromB64 will decode a B64 string (from a HTTP request header) and will build an IdentityChallenge from it
func IdentityChallengeFromB64(i string) identityChallenge {
	msg, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		return identityChallenge{}
	}
	ret := identityChallenge{}
	err = protocol.DecodeReflect(msg, &ret)
	if err != nil {
		return identityChallenge{}
	}
	return ret
}

// Verify checks that the signature included in the identityChallenge was indeed created by the included Key
func (i identityChallenge) Verify() bool {
	return i.Key.VerifyBytes(i.signableBytes(), i.Signature)
}

// NewIdentityResponseChallengeAndHeader will generate an Identity Challenge Response from the given Identity Challenge,
// and will return the "Response Challenge" (a novel challenge) and the signed and b64 encoded header for response
func NewIdentityResponseChallengeAndHeader(keys *crypto.SignatureSecrets, c identityChallenge) ([32]byte, string) {
	r := identityChallengeResponse{
		Key:               keys.SignatureVerifier,
		Challenge:         c.Challenge,
		ResponseChallenge: [32]byte{},
	}
	crypto.RandBytes(r.ResponseChallenge[:])
	return r.ResponseChallenge, r.signAndEncodeB64(keys)
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

// IdentityChallengeResponseFromB64 will return an Identity Challenge Response from the B64 header string
func IdentityChallengeResponseFromB64(i string) identityChallengeResponse {
	msg, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		return identityChallengeResponse{}
	}
	ret := identityChallengeResponse{}
	err = protocol.DecodeReflect(msg, &ret)
	if err != nil {
		return identityChallengeResponse{}
	}
	return ret
}

// Verify checks that the signature included in the identityChallengeResponse was indeed created by the included Key
func (i identityChallengeResponse) Verify() bool {
	return i.Key.VerifyBytes(i.signableBytes(), i.Signature)
}

// SendIdentityChallengeVerification sends the 3rd (final) message for signature handshake between two peers.
// it simply sends across a signature of a challenge which the potential peer has given it to sign.
// at this stage in the peering process, the peer hasn't had an opportunity to verify our supposed identity
func SendIdentityChallengeVerification(wp *wsPeer, sig crypto.Signature) error {
	mbytes := append([]byte(protocol.NetIDVerificationTag), sig[:]...)
	sent := wp.writeNonBlock(context.Background(), mbytes, true, crypto.Digest{}, time.Now())
	if !sent {
		return fmt.Errorf("could not send identity challenge verification")
	}
	return nil
}

// identityVerificationHandler receives a signature over websocket, and confirms it matches the
// sender's claimed identity and the challenge that was assigned to it. If it verifies, the network will mark it verified,
// and will do any related record keeping it needs
func identityVerificationHandler(message IncomingMessage) OutgoingMessage {
	peer := message.Sender.(*wsPeer)
	// avoid doing work (crypto and potentially taking a lock) if the peer is already verified
	if atomic.LoadUint32(&peer.identityVerified) == 1 {
		return OutgoingMessage{}
	}
	sig := crypto.Signature{}
	copy(sig[:], message.Data[:64])
	if peer.identity.VerifyBytes(peer.identityChallenge[:], sig) {
		peer.IdentityVerified()
		if peer.net != nil {
			peer.net.MarkVerified(peer)
		}
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
type publicKeyIdentTracker struct {
	peersByID map[crypto.PublicKey]*wsPeer
	lock      deadlock.RWMutex
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
	t.lock.Lock()
	defer t.lock.Unlock()
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
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.peersByID[p.identity] == p {
		delete(t.peersByID, p.identity)
	}
}
