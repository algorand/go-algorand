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
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
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
func (i identityChallenge) Verify() error {
	verified := i.Key.VerifyBytes(i.signableBytes(), i.Signature)
	if !verified {
		return fmt.Errorf("include signature does not verify identity challenge")
	}
	return nil
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
func (i identityChallengeResponse) Verify() error {
	b := i.signableBytes()
	verified := i.Key.VerifyBytes(b, i.Signature)
	if !verified {
		return fmt.Errorf("included signature does not verify identity challenge")
	}
	return nil
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

// identityVerificationHandler recieves a signature over websocket, and confirms it matches the
// sender's identity and the challenge that was assigned to it. If it verifies, the network will mark it verified,
// and will do any related record keeping it needs
func identityVerificationHandler(message IncomingMessage) OutgoingMessage {
	peer := message.Sender.(*wsPeer)
	sig := crypto.Signature{}
	copy(sig[:], message.Data[:64])
	if peer.identity.VerifyBytes(peer.identityChallenge[:], sig) {
		peer.net.MarkVerified(peer)
	}
	return OutgoingMessage{}
}

var identityHandlers = []TaggedMessageHandler{
	{protocol.NetIDVerificationTag, HandlerFunc(identityVerificationHandler)},
}
