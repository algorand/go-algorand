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
	"fmt"
	"net/http"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// netidentity.go implements functionality to participate in an "Identity Challenge Exchange"
// with the purpose of identifying redundant connections between peers, and preventing them.
// The identity challenge exchange protocol is a 3 way handshake that exchanges signed messages.
//
// Message 1 (Identity Challenge): when a request is made to start a gossip connection, an
// identityChallengeSigned message is added to HTTP request headers, containing:
// - a 32 byte random challenge
// - the requester's "identity" PublicKey
// - the PublicAddress of the intended recipient
// - Signature on the above by the requester's PublicKey
//
// Message 2 (Identity Challenge Response): when responding to the gossip connection request,
// if the identity challenge is valid, an identityChallengeResponseSigned message is added
// to the HTTP response headers, containing:
// - the original 32 byte random challenge from Message 1
// - a new "response" 32 byte random challenge
// - the responder's "identity" PublicKey
// - Signature on the above by the responder's PublicKey
//
// Message 3 (Identity Verification): if the identityChallengeResponse is valid, the requester
// sends a NetIDVerificationTag message over websockets to verify it owns its PublicKey, with:
// - Signature on the response challenge from Message 2, using the requester's PublicKey
//
// Upon receipt of Message 2, the requester has enough data to consider the responder's identity "verified".
// Upon receipt of Message 3, the responder has enough data to consider the requester's identity "verified".
// At each of these steps, if the peer's identity was verified, wsNetwork will attempt to add it to the
// identityTracker, which maintains a single peer per identity PublicKey. If the identity is already in use
// by another connected peer, we know this connection is a duplicate, and can be closed.
//
// Protocol Enablement:
// This exchange is optional, and is enabled by setting the configuration value "PublicAddress" to match the
// node's public endpoint address stored in other peers' phonebooks (like "r-aa.algorand-mainnet.network:4160").
//
// Protocol Error Handling:
// Message 1
// - If the Message is not included, assume the peer does not use identity exchange, and peer without attaching an identityChallengeResponse
// - If the Address included in the challenge is not this node's PublicAddress, peering continues without identity exchange.
//   this is so that if an operator misconfigures PublicAddress, it does not decline well meaning peering attempts
// - If the Message is malformed or cannot be decoded, the peering attempt is stopped
// - If the Signature in the challenge does not verify to the included key, the peering attempt is stopped
//
// Message 2
// - If the Message is not included, assume the peer does not use identity exchange, and do not send Message 3
// - If the Message is malformed or cannot be decoded, the peering attempt is stopped
// - If the original 32 byte challenge does not match the one sent in Message 1, the peering attempt is stopped
// - If the Signature in the challenge does not verify to the included key, the peering attempt is stopped
//
// Message 3
// - If the Message is malformed or cannot be decoded, the peer is disconnected
// - If the Signature in the challenge does not verify peer's assumed PublicKey and assigned Challenge Bytes, the peer is disconnected
// - If the Message is not received, no action is taken to disconnect the peer.

const maxAddressLen = 256 + 32 // Max DNS (255) + margin for port specification

// identityChallengeValue is 32 random bytes used for identity challenge exchange
type identityChallengeValue [32]byte

func newIdentityChallengeValue() identityChallengeValue {
	var ret identityChallengeValue
	crypto.RandBytes(ret[:])
	return ret
}

type identityChallengeScheme interface {
	AttachChallenge(attachTo http.Header, addr string) identityChallengeValue
	VerifyRequestAndAttachResponse(attachTo http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error)
	VerifyResponse(h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error)
}

// identityChallengePublicKeyScheme implements IdentityChallengeScheme by
// exchanging and verifying public key challenges and attaching them to headers,
// or returning the message payload to be sent
type identityChallengePublicKeyScheme struct {
	dedupName    string
	identityKeys *crypto.SignatureSecrets
}

// NewIdentityChallengeScheme will create a default Identification Scheme
func NewIdentityChallengeScheme(dn string) *identityChallengePublicKeyScheme {
	// without an deduplication name, there is no identityto manage, so just return an empty scheme
	if dn == "" {
		return &identityChallengePublicKeyScheme{}
	}
	var seed crypto.Seed
	crypto.RandBytes(seed[:])

	return &identityChallengePublicKeyScheme{
		dedupName:    dn,
		identityKeys: crypto.GenerateSignatureSecrets(seed),
	}
}

// AttachChallenge will generate a new identity challenge and will encode and attach the challenge
// as a header. It returns the identityChallengeValue used for this challenge, so the network can
// confirm it later (by passing it to VerifyResponse), or returns an empty challenge if dedupName is
// not set.
func (i identityChallengePublicKeyScheme) AttachChallenge(attachTo http.Header, addr string) identityChallengeValue {
	if i.dedupName == "" || addr == "" {
		return identityChallengeValue{}
	}
	c := identityChallenge{
		Key:           i.identityKeys.SignatureVerifier,
		Challenge:     newIdentityChallengeValue(),
		PublicAddress: []byte(addr),
	}

	attachTo.Add(IdentityChallengeHeader, c.signAndEncodeB64(i.identityKeys))
	return c.Challenge
}

// VerifyRequestAndAttachResponse checks headers for an Identity Challenge, and verifies:
// * the provided challenge bytes matches the one encoded in the header
// * the identity challenge verifies against the included key
// * the "Address" field matches what this scheme expects
// once verified, it will attach the header to the "attach" header
// and will return the challenge and identity of the peer for recording
// or returns empty values if the header did not end up getting set
func (i identityChallengePublicKeyScheme) VerifyRequestAndAttachResponse(attachTo http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error) {
	// if dedupName is not set, this scheme is not configured to exchange identity
	if i.dedupName == "" {
		return identityChallengeValue{}, crypto.PublicKey{}, nil
	}
	// if the headerString is not populated, the peer isn't participating in identity exchange
	headerString := h.Get(IdentityChallengeHeader)
	if headerString == "" {
		return identityChallengeValue{}, crypto.PublicKey{}, nil
	}
	// decode the header to an identityChallenge
	msg, err := base64.StdEncoding.DecodeString(headerString)
	if err != nil {
		return identityChallengeValue{}, crypto.PublicKey{}, err
	}
	idChal := identityChallengeSigned{}
	err = protocol.Decode(msg, &idChal)
	if err != nil {
		return identityChallengeValue{}, crypto.PublicKey{}, err
	}
	if !idChal.Verify() {
		return identityChallengeValue{}, crypto.PublicKey{}, fmt.Errorf("identity challenge incorrectly signed")
	}
	// if the address is not meant for this host, return without attaching headers,
	// but also do not emit an error. This is because if an operator were to incorrectly
	// specify their dedupName, it could result in inappropriate disconnections from valid peers
	if string(idChal.Msg.PublicAddress) != i.dedupName {
		return identityChallengeValue{}, crypto.PublicKey{}, nil
	}
	// make the response object, encode it and attach it to the header
	r := identityChallengeResponse{
		Key:               i.identityKeys.SignatureVerifier,
		Challenge:         idChal.Msg.Challenge,
		ResponseChallenge: newIdentityChallengeValue(),
	}
	attachTo.Add(IdentityChallengeHeader, r.signAndEncodeB64(i.identityKeys))
	return r.ResponseChallenge, idChal.Msg.Key, nil
}

// VerifyResponse will decode the identity challenge header from an HTTP response (containing an
// encoding of identityChallengeResponseSigned) and confirm it has a valid signature, and that the
// provided challenge (generated and added to the HTTP request by AttachChallenge) matches the one
// found in the header. If the response can be verified, it returns the identity of the peer and an
// encoded identityVerificationMessage to send to the peer. Otherwise, it returns empty values.
func (i identityChallengePublicKeyScheme) VerifyResponse(h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error) {
	// if we are not participating in identity challenge exchange, do nothing (no error and no value)
	if i.dedupName == "" {
		return crypto.PublicKey{}, []byte{}, nil
	}
	headerString := h.Get(IdentityChallengeHeader)
	// if the header is not populated, assume the peer is not participating in identity exchange
	if headerString == "" {
		return crypto.PublicKey{}, []byte{}, nil
	}
	msg, err := base64.StdEncoding.DecodeString(headerString)
	if err != nil {
		return crypto.PublicKey{}, []byte{}, err
	}
	resp := identityChallengeResponseSigned{}
	err = protocol.Decode(msg, &resp)
	if err != nil {
		return crypto.PublicKey{}, []byte{}, err
	}
	if resp.Msg.Challenge != c {
		return crypto.PublicKey{}, []byte{}, fmt.Errorf("challenge response did not contain originally issued challenge value")
	}
	if !resp.Verify() {
		return crypto.PublicKey{}, []byte{}, fmt.Errorf("challenge response incorrectly signed ")
	}
	return resp.Msg.Key, i.identityVerificationMessage(resp.Msg.ResponseChallenge), nil
}

// identityVerificationMessage generates the 3rd message of the challenge exchange,
// which a wsNetwork can then send to a peer in order to verify their own identity.
// It is prefixed with the ID Verification tag and returned ready-to-send
func (i *identityChallengePublicKeyScheme) identityVerificationMessage(c identityChallengeValue) []byte {
	signedMsg := identityVerificationMessage{ResponseChallenge: c}.Sign(i.identityKeys)
	return append([]byte(protocol.NetIDVerificationTag), protocol.Encode(&signedMsg)...)
}

// The initial challenge object, giving the peer a challenge to return (Challenge),
// the presumed identity of this node (Key), the intended recipient (Address).
type identityChallenge struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Key           crypto.PublicKey       `codec:"pk"`
	Challenge     identityChallengeValue `codec:"c"`
	PublicAddress []byte                 `codec:"a,allocbound=maxAddressLen"`
}

// identityChallengeSigned wraps an identityChallenge with a signature, similar to SignedTxn and
// netPrioResponseSigned.
type identityChallengeSigned struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Msg       identityChallenge `codec:"ic"`
	Signature crypto.Signature  `codec:"sig"`
}

// The response to an identityChallenge, containing the responder's public key, the original
// requestor's challenge, and a new challenge for the requestor.
type identityChallengeResponse struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Key               crypto.PublicKey       `codec:"pk"`
	Challenge         identityChallengeValue `codec:"c"`
	ResponseChallenge identityChallengeValue `codec:"rc"`
}

type identityChallengeResponseSigned struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Msg       identityChallengeResponse `codec:"icr"`
	Signature crypto.Signature          `codec:"sig"`
}

type identityVerificationMessage struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ResponseChallenge identityChallengeValue `codec:"rc"`
}

type identityVerificationMessageSigned struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Msg       identityVerificationMessage `codec:"ivm"`
	Signature crypto.Signature            `codec:"sig"`
}

func (i identityChallenge) signAndEncodeB64(s *crypto.SignatureSecrets) string {
	signedChal := i.Sign(s)
	return base64.StdEncoding.EncodeToString(protocol.Encode(&signedChal))
}

func (i identityChallenge) Sign(secrets *crypto.SignatureSecrets) identityChallengeSigned {
	return identityChallengeSigned{Msg: i, Signature: secrets.Sign(i)}
}

func (i identityChallenge) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.NetIdentityChallenge, protocol.Encode(&i)
}

// Verify checks that the signature included in the identityChallenge was indeed created by the included Key
func (i identityChallengeSigned) Verify() bool {
	return i.Msg.Key.Verify(i.Msg, i.Signature)
}

func (i identityChallengeResponse) signAndEncodeB64(s *crypto.SignatureSecrets) string {
	signedChalResp := i.Sign(s)
	return base64.StdEncoding.EncodeToString(protocol.Encode(&signedChalResp))
}

func (i identityChallengeResponse) Sign(secrets *crypto.SignatureSecrets) identityChallengeResponseSigned {
	return identityChallengeResponseSigned{Msg: i, Signature: secrets.Sign(i)}
}

func (i identityChallengeResponse) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.NetIdentityChallengeResponse, protocol.Encode(&i)
}

// Verify checks that the signature included in the identityChallengeResponse was indeed created by the included Key
func (i identityChallengeResponseSigned) Verify() bool {
	return i.Msg.Key.Verify(i.Msg, i.Signature)
}

func (i identityVerificationMessage) Sign(secrets *crypto.SignatureSecrets) identityVerificationMessageSigned {
	return identityVerificationMessageSigned{Msg: i, Signature: secrets.Sign(i)}
}

func (i identityVerificationMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.NetIdentityVerificationMessage, protocol.Encode(&i)
}

// Verify checks that the signature included in the identityVerificationMessage was indeed created by the included Key
func (i identityVerificationMessageSigned) Verify(key crypto.PublicKey) bool {
	return key.Verify(i.Msg, i.Signature)
}

// identityVerificationHandler receives a signature over websocket, and confirms it matches the
// sender's claimed identity and the challenge that was assigned to it. If the identity is available,
// the peer is loaded into the identity tracker. Otherwise, we ask the network to disconnect the peer.
func identityVerificationHandler(message IncomingMessage) OutgoingMessage {
	wn := message.Net.(*WebsocketNetwork)

	peer := message.Sender.(*wsPeer)
	// avoid doing work (crypto and potentially taking a lock) if the peer is already verified
	if peer.identityVerified.Load() == 1 {
		return OutgoingMessage{}
	}
	localAddr, _ := peer.net.Address()
	msg := identityVerificationMessageSigned{}
	err := protocol.Decode(message.Data, &msg)
	if err != nil {
		networkPeerIdentityError.Inc(nil)
		peer.log.With("err", err).With("remote", peer.OriginAddress()).With("local", localAddr).Warn("peer identity verification could not be decoded, disconnecting")
		return OutgoingMessage{Action: Disconnect, reason: disconnectBadIdentityData}
	}
	if peer.identityChallenge != msg.Msg.ResponseChallenge {
		networkPeerIdentityError.Inc(nil)
		peer.log.With("remote", peer.OriginAddress()).With("local", localAddr).Warn("peer identity verification challenge does not match, disconnecting")
		return OutgoingMessage{Action: Disconnect, reason: disconnectBadIdentityData}
	}
	if !msg.Verify(peer.identity) {
		networkPeerIdentityError.Inc(nil)
		peer.log.With("remote", peer.OriginAddress()).With("local", localAddr).Warn("peer identity verification is incorrectly signed, disconnecting")
		return OutgoingMessage{Action: Disconnect, reason: disconnectBadIdentityData}
	}
	peer.identityVerified.Store(1)
	// if the identity could not be claimed by this peer, it means the identity is in use
	wn.peersLock.Lock()
	ok := wn.identityTracker.setIdentity(peer)
	wn.peersLock.Unlock()
	if !ok {
		networkPeerIdentityDisconnect.Inc(nil)
		peer.log.With("remote", peer.OriginAddress()).With("local", localAddr).Warn("peer identity already in use, disconnecting")
		return OutgoingMessage{Action: Disconnect, reason: disconnectDuplicateConnection}
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
