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

// ProtocolConectionIdentityChallengeHeader is used to exchange IdentityChallenges
const ProtocolConectionIdentityChallengeHeader = "X-Algorand-IdentityChallenge"

// minimumProtocolVersion is used to evaluate if a peer's supported protocol
// should include identityChallenge exchange
var minimumProtocolVersion = [2]int64{2, 2}

func shouldSupportIdentityChallenge(v string) bool {
	maj, min, err := versionToMajorMinor(v)
	if err != nil {
		return false
	}
	if maj < minimumProtocolVersion[0] {
		return false
	}
	if maj > minimumProtocolVersion[0] {
		return true
	}
	if min < minimumProtocolVersion[1] {
		return false
	}
	return true
}

type identityChallenge struct {
	Key       crypto.PublicKey `codec:"pk"`
	Challenge [32]byte         `codec:"c"`
	Signature crypto.Signature `codec:"s"`
}

type identityChallengeResponse struct {
	identityChallenge
	ResponseChallenge [32]byte `codec:"rc"`
}

// NewIdentityChallenge creates an IdentityChallenge with randomized 32byte Challenge
func NewIdentityChallenge(p crypto.PublicKey) identityChallenge {
	c := identityChallenge{
		Key:       p,
		Challenge: [32]byte{},
	}
	crypto.RandBytes(c.Challenge[:])
	return c
}

func (i identityChallenge) signableBytes() []byte {
	return bytes.Join([][]byte{
		i.Challenge[:],
		i.Key[:],
	},
		[]byte(":"))
}

func (i identityChallenge) sign(s *crypto.SignatureSecrets) crypto.Signature {
	return s.SignBytes(i.signableBytes())
}

func (i identityChallenge) verify() error {
	b := i.signableBytes()
	verified := i.Key.VerifyBytes(b, i.Signature)
	if !verified {
		return fmt.Errorf("included signature does not verify identity challenge")
	}
	return nil
}

// SignAndEncodeB64 signs the identityChallenge, attaches a signature, and converts
// the structure to a b64 and msgpk'd string to be included as a header
func (i *identityChallenge) SignAndEncodeB64(s *crypto.SignatureSecrets) string {
	i.Signature = i.sign(s)
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	return b64enc
}

// IdentityChallengeFromB64 will return an Identity Challenge from the B64 header string
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

// NewIdentityChallengeResponse creates an IdentityChallengeResponse from a received identityChallenge
func NewIdentityChallengeResponse(p crypto.PublicKey, id identityChallenge) identityChallengeResponse {
	c := identityChallengeResponse{
		identityChallenge: identityChallenge{
			Key:       p,
			Challenge: id.Challenge,
		},
		ResponseChallenge: [32]byte{},
	}
	crypto.RandBytes(c.ResponseChallenge[:])
	return c
}

func (i identityChallengeResponse) signableBytes() []byte {
	return bytes.Join([][]byte{
		i.Challenge[:],
		i.ResponseChallenge[:],
		i.Key[:],
	},
		[]byte(":"))
}

func (i identityChallengeResponse) sign(s *crypto.SignatureSecrets) crypto.Signature {
	return s.SignBytes(i.signableBytes())
}

func (i identityChallengeResponse) verify() error {
	b := i.signableBytes()
	verified := i.Key.VerifyBytes(b, i.Signature)
	if !verified {
		return fmt.Errorf("included signature does not verify identity challenge")
	}
	return nil
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

func (i *identityChallengeResponse) SignAndEncodeB64(s *crypto.SignatureSecrets) string {
	i.Signature = i.sign(s)
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	return b64enc
}

// SendIdentityChallengeVerification will send a signaturure of a challenge which was assigned
// by the wsPeer
func SendIdentityChallengeVerification(wp *wsPeer, sig crypto.Signature) error {
	mbytes := append([]byte(protocol.NetIDVerificationTag), sig[:]...)
	sent := wp.writeNonBlock(context.Background(), mbytes, true, crypto.Digest{}, time.Now())
	if !sent {
		return fmt.Errorf("could not send identity challenge verification")
	}
	return nil
}

// identityVerificationHandler processes identity challenge verification messages,
// which are websocket messages containing a signed signature which should match with the
// peer's assigned challenge
func identityVerificationHandler(message IncomingMessage) OutgoingMessage {
	peer := message.Sender.(*wsPeer)
	sig := crypto.Signature{}
	copy(sig[:], message.Data[:64])
	verified := peer.identity.VerifyBytes(peer.identityChallenge[:], sig)
	if verified {
		peer.IdentityVerified()
	}
	return OutgoingMessage{}
}

var identityHandlers = []TaggedMessageHandler{
	{protocol.NetIDVerificationTag, HandlerFunc(identityVerificationHandler)},
}
