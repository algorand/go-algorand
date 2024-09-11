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

package agreement

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func BenchmarkVoteDecoding(b *testing.B) {
	oneTimeSecrets := crypto.GenerateOneTimeSignatureSecrets(300, 1000)
	id := crypto.OneTimeSignatureIdentifier{
		Batch: 1000,

		// Avoid generating the last few offsets (in a batch size of 256), so we can increment correctly
		Offset: crypto.RandUint64() % 250,
	}
	proposal := unauthenticatedProposal{
		OriginalPeriod: period(crypto.RandUint64() % 250),
	}

	var vrfProof crypto.VRFProof
	crypto.SystemRNG.RandBytes(vrfProof[:])

	var sendAddr basics.Address
	crypto.SystemRNG.RandBytes(sendAddr[:])

	uv := unauthenticatedVote{
		R: rawVote{
			Sender: sendAddr,
			Round:  basics.Round(356),
			Period: period(4),
			Step:   step(3),
			Proposal: proposalValue{
				OriginalPeriod:   period(3),
				OriginalProposer: poolAddr,
				BlockDigest:      crypto.Hash([]byte{1, 2, 3}),
				EncodingDigest:   crypto.Hash([]byte{5, 6, 7}),
			},
		},
		Cred: committee.UnauthenticatedCredential{
			Proof: vrfProof,
		},
		Sig: oneTimeSecrets.Sign(id, proposal),
	}

	msgBytes := protocol.Encode(&uv)

	// make sure we know how to decode this correctly.
	iVote, err := decodeVote(msgBytes)
	require.Nil(b, err)
	decodedVote := iVote.(unauthenticatedVote)
	require.Equal(b, uv.R.Period, decodedVote.R.Period)

	// and now, let's measure the performance.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeVote(msgBytes)
	}
}

// TestMessageBackwardCompatibility ensures MessageHandle field can be
// properly decoded from message.
// This test is only needed for agreement state serialization switch from reflection to msgp.
func TestMessageBackwardCompatibility(t *testing.T) {
	partitiontest.PartitionTest(t)

	type messageMetadata struct {
		raw network.IncomingMessage
	}

	encoded, err := base64.StdEncoding.DecodeString("iaZCdW5kbGWAr0NvbXBvdW5kTWVzc2FnZYKoUHJvcG9zYWyApFZvdGWArU1lc3NhZ2VIYW5kbGWAqFByb3Bvc2FsgKNUYWeiUFC1VW5hdXRoZW50aWNhdGVkQnVuZGxlgLdVbmF1dGhlbnRpY2F0ZWRQcm9wb3NhbICzVW5hdXRoZW50aWNhdGVkVm90ZYCkVm90ZYA=")
	require.NoError(t, err)

	// run on master f57a276 to get the encoded data for above
	// msg := message{
	// 	MessageHandle: &messageMetadata{raw: network.IncomingMessage{Tag: protocol.Tag("mytag"), Data: []byte("some data")}},
	// 	Tag:           protocol.ProposalPayloadTag,
	// }

	// result := protocol.EncodeReflect(&msg)
	// fmt.Println(base64.StdEncoding.EncodeToString(result))

	// messages for all rounds after this change should not have MessageHandle set so clearing it out and re-encoding/decoding it should yield this
	targetMessage := message{
		Tag: protocol.ProposalPayloadTag,
	}

	require.Containsf(t, string(encoded), "MessageHandle", "encoded message does not contain MessageHandle field")
	var m1, m2, m3, m4 message
	// Both msgp and reflection should decode the message containing old MessageHandle successfully
	err = protocol.Decode(encoded, &m1)
	require.NoError(t, err)
	err = protocol.DecodeReflect(encoded, &m2)
	require.NoError(t, err)
	// after setting MessageHandle to nil both should re-encode and decode to same values
	m1.MessageHandle = nil
	m2.MessageHandle = nil
	e1 := protocol.Encode(&m1)
	e2 := protocol.EncodeReflect(&m2)
	require.Equal(t, e1, e2)
	require.NotContainsf(t, string(e1), "MessageHandle", "encoded message still contains MessageHandle field")
	err = protocol.DecodeReflect(e1, &m3)
	require.NoError(t, err)
	err = protocol.Decode(e2, &m4)
	require.NoError(t, err)
	require.Equal(t, m3, m4)
	require.Equal(t, m3, targetMessage)
}
