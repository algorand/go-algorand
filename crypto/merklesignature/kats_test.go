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

package merklesignature

import (
	"flag"
	"fmt"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"testing"
)

type mssKat struct {
	publicKey          []byte
	ctSignature        []byte
	ephemeralKey       []byte
	vcIndex            uint64
	correspondingRound uint64
	proofDepth         uint8
	proofBytes         []byte
	message            []byte
}

func sliceToHex(b []byte) string {
	str := "["
	for i := 0; i < len(b)-1; i++ {
		str += fmt.Sprintf("0x%.2x, ", b[i])
	}
	str += fmt.Sprintf("0x%.2x]", b[len(b)-1])
	return str
}

// String converts kat to a pretty-printable string
func (kat mssKat) String() string {
	var asString string
	asString = fmt.Sprintf("MSS public key (root): %v  \n", sliceToHex(kat.publicKey[:]))
	asString += fmt.Sprintf("ctSignature: %v  \n", sliceToHex(kat.ctSignature))
	asString += fmt.Sprintf("ephemeral public key: %v \n ", sliceToHex(kat.ephemeralKey))
	asString += fmt.Sprintf("correspondingRound: 0x%x \n", kat.correspondingRound)
	asString += fmt.Sprintf("VC index: 0x%x \n", kat.vcIndex)
	asString += fmt.Sprintf("Proof Depth: 0x%x \n", kat.proofDepth)
	asString += fmt.Sprintf("Proof: %v \n", sliceToHex(kat.proofBytes))
	asString += fmt.Sprintf("Message: %v \n", sliceToHex(kat.message))

	return asString
}

func extractMssSignatureParts(signature Signature) ([]byte, []byte, []byte, uint8, error) {
	ctSignature, err := signature.VerifyingKey.GetSignatureFixedLengthHashableRepresentation(signature.Signature)
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

	interval := config.Consensus[protocol.ConsensusFuture].CompactCertRounds
	stateProofSecrets, err := New(startRound, startRound+(interval*numOfKeys)-1, interval)
	if err != nil {
		return mssKat{}, fmt.Errorf("error: %w", err)
	}

	keyForRound := stateProofSecrets.GetSigner(atRound)
	if keyForRound == nil {
		return mssKat{}, fmt.Errorf("error: There is no key for round %d", atRound)
	}

	signature, err := keyForRound.SignBytes(messageToSign)
	verifier := stateProofSecrets.GetVerifier()
	ctSignature, pk, proof, proofDepth, err := extractMssSignatureParts(signature)
	if err != nil {
		return mssKat{}, fmt.Errorf("error while formating mss signature %w", err)
	}

	return mssKat{publicKey: verifier[:],
		ctSignature:        ctSignature,
		ephemeralKey:       pk,
		vcIndex:            signature.VectorCommitmentIndex,
		correspondingRound: atRound,
		proofDepth:         proofDepth,
		proofBytes:         proof,
		message:            messageToSign}, nil
}

var shouldGenerateKATs bool

func init() {
	flag.BoolVar(&shouldGenerateKATs, "kat", false, "runs Merkle Signature Scheme KATS")
}

func TestGenerateKat(t *testing.T) {
	partitiontest.PartitionTest(t)

	if !shouldGenerateKATs {
		t.Skip()
	}
	kat, _ := generateMssKat(256, 512, 9, []byte("test"))
	fmt.Println(kat)
}
