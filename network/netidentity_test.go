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
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityChallengeSignEncodeDecode(t *testing.T) {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)
	k := (crypto.PublicKey)(secrets.SignatureVerifier)
	chal := NewIdentityChallenge(k)

	chalEncoded := chal.SignAndEncodeB64(secrets)
	assert.NotEmpty(t, chalEncoded)

	chal2 := IdentityChallengeFromB64(chalEncoded)
	assert.Equal(t, chal.Challenge, chal2.Challenge)
	assert.Equal(t, chal.Key, chal2.Key)

	// sign this ourselves to confirm signing is as expected,
	// and because the object is not signed until encoding
	chalSignature := secrets.SignBytes(chal.signableBytes())
	assert.Equal(t, chalSignature, chal2.Signature)
}

func TestIdentityChallengeResponseSignEncodeDecode(t *testing.T) {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	chalSecrets := crypto.GenerateSignatureSecrets(seed)
	chal := NewIdentityChallenge((crypto.PublicKey)(chalSecrets.SignatureVerifier))

	crypto.RandBytes(seed[:])
	respSecrets := crypto.GenerateSignatureSecrets(seed)
	chalResp := NewIdentityChallengeResponse((crypto.PublicKey)(chalSecrets.SignatureVerifier), chal)

	chalRespEncoded := chalResp.SignAndEncodeB64(respSecrets)
	assert.NotEmpty(t, chalRespEncoded)

	chalResp2 := IdentityChallengeResponseFromB64(chalRespEncoded)
	assert.Equal(t, chalResp.Challenge, chalResp2.Challenge)
	assert.Equal(t, chalResp.ResponseChallenge, chalResp2.ResponseChallenge)
	assert.Equal(t, chalResp.Key, chalResp2.Key)

	respSignature := respSecrets.SignBytes(chalResp.signableBytes())
	assert.Equal(t, respSignature, chalResp2.Signature)
}

func TestIdentityChallengeVerify(t *testing.T) {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	secrets := crypto.GenerateSignatureSecrets(seed)
	k := (crypto.PublicKey)(secrets.SignatureVerifier)
	chal := NewIdentityChallenge(k)

	// Should fail to verify if the signature is not correct
	crypto.RandBytes(chal.Signature[:])
	require.Error(t, chal.verify())

	// Should verify by signing the signableBytes of the object
	chal.Signature = secrets.SignBytes(chal.signableBytes())
	require.NoError(t, chal.verify())
}

func TestIdentityChallengeResponseVerify(t *testing.T) {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	chalSecrets := crypto.GenerateSignatureSecrets(seed)
	chal := NewIdentityChallenge((crypto.PublicKey)(chalSecrets.SignatureVerifier))

	crypto.RandBytes(seed[:])
	respSecrets := crypto.GenerateSignatureSecrets(seed)
	chalResp := NewIdentityChallengeResponse((crypto.PublicKey)(respSecrets.SignatureVerifier), chal)

	crypto.RandBytes(chalResp.Signature[:])
	require.Error(t, chalResp.verify())

	chalResp.Signature = respSecrets.SignBytes(chalResp.signableBytes())
	fmt.Println(chalResp.Signature)
	fmt.Println(chalResp.Key)
	require.NoError(t, chalResp.verify())
}

func TestIdentityVerificationHandler(t *testing.T) {
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
	assert.Equal(t, uint32(1), p.identityVerified)
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
	assert.Equal(t, uint32(0), p.identityVerified)
}
