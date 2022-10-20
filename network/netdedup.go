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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// Initial Deduplication Header
const ProtocolConectionIdentityChallengeHeader = "X-Algorand-IdentityChallenge"

type identityChallenge struct {
	Nonce     int      `codec:"n"`
	Key       string   `codec:"k"`
	Challenge [32]byte `codec:"c"`
}

type identityChallengeResponse struct {
	identityChallenge
	ResponseChallenge [32]byte `codec:"rc"`
}

func NewIdentityChallenge() identityChallenge {
	c := identityChallenge{
		Nonce:     1,
		Key:       "myKey",
		Challenge: [32]byte{},
	}
	crypto.RandBytes(c.Challenge[:])
	return c
}

func NewIdentityChallengeResponse() identityChallengeResponse {
	c := identityChallengeResponse{
		identityChallenge: identityChallenge{
			Nonce:     2,
			Key:       "myKeyResponse",
			Challenge: [32]byte{},
		},
		ResponseChallenge: [32]byte{},
	}
	crypto.RandBytes(c.ResponseChallenge[:])
	return c
}

func IdentityChallengeFromB64(i string) identityChallenge {
	msg, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		return identityChallenge{}
	}
	ret := identityChallenge{}
	protocol.DecodeReflect(msg, &ret)
	return ret
}

func IdentityChallengeResponseFromB64(i string) identityChallengeResponse {
	msg, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		return identityChallengeResponse{}
	}
	ret := identityChallengeResponse{}
	protocol.DecodeReflect(msg, &ret)
	return ret
}

func (i identityChallengeResponse) EncodeB64() string {
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	return b64enc
}

func (i identityChallenge) EncodeB64() string {
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	return b64enc
}
