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

package merklesignature

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type mssKat struct {
	PublicKey          []byte
	KeyLifetime        uint64
	CtSignature        []byte
	EphemeralKey       []byte
	VcIndex            uint64
	CorrespondingRound uint64
	ProofDepth         uint8
	ProofBytes         []byte
	Message            []byte
}

func extractMssSignatureParts(signature Signature) ([]byte, []byte, []byte, uint8, error) {
	ctSignature, err := signature.Signature.GetFixedLengthHashableRepresentation()
	if err != nil {
		return nil, nil, nil, 0, err
	}

	pk := signature.VerifyingKey.GetFixedLengthHashableRepresentation()
	proof := signature.Proof.GetFixedLengthHashableRepresentation()
	proofDepth := proof[0]
	proof = proof[1:]

	return ctSignature, pk, proof, proofDepth, nil
}

func generateMssKat(startRound, atRound, numOfKeys uint64, messageToSign []byte) (mssKat, error) {
	if startRound > atRound {
		return mssKat{}, fmt.Errorf("error: Signature round cann't be smaller then start round")
	}

	interval := config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval
	stateProofSecrets, err := New(startRound, startRound+(interval*numOfKeys)-1, interval)
	if err != nil {
		return mssKat{}, fmt.Errorf("error: %w", err)
	}

	keyForRound := stateProofSecrets.GetSigner(atRound)
	if keyForRound == nil {
		return mssKat{}, fmt.Errorf("error: There is no key for round %d", atRound)
	}

	signature, err := keyForRound.SignBytes(messageToSign)
	if err != nil {
		return mssKat{}, fmt.Errorf("error while formating mss signature %w", err)
	}
	verifier := stateProofSecrets.GetVerifier()
	ctSignature, pk, proof, proofDepth, err := extractMssSignatureParts(signature)
	if err != nil {
		return mssKat{}, fmt.Errorf("error while formating mss signature %w", err)
	}

	return mssKat{
		PublicKey:          verifier.Commitment[:],
		KeyLifetime:        KeyLifetimeDefault,
		CtSignature:        ctSignature,
		EphemeralKey:       pk,
		VcIndex:            signature.VectorCommitmentIndex,
		CorrespondingRound: atRound,
		ProofDepth:         proofDepth,
		ProofBytes:         proof,
		Message:            messageToSign}, nil
}

func TestGenerateKat(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	// This test produces MSS samples for the SNARK verifier.
	// it will only run explicitly by:
	//
	//   GEN_KATS=x go test -v . -run=GenerateKat -count=1
	if os.Getenv("GEN_KATS") == "" {
		t.Skip("Skipping; GEN_KATS not set")
	}

	kat, err := generateMssKat(256, 512, 9, []byte("test"))
	a.NoError(err)

	katAsJSON, err := json.MarshalIndent(kat, "", "\t")
	a.NoError(err)

	fmt.Println(string(katAsJSON))
}
