package crypto

import (
	"github.com/algorand/go-algorand/protocol"
	"testing"
)

func TestSignatureAlgorithmMarshaling(t *testing.T) {
	algorithm := SignatureAlgorithm{
		Type: placeHolderType,
		S:    GeneratePlaceHolderKey(),
	}
	z := protocol.Encode(&algorithm)
	newAlgorithm := SignatureAlgorithm{}
	if err := protocol.Decode(z, &newAlgorithm); err != nil {
		t.Error(err)
		return
	}
	if newAlgorithm.Type != algorithm.Type {
		t.Errorf("expected %v, actual: %v", algorithm.Type, newAlgorithm.Type)
		return
	}

	if *(newAlgorithm.S.(*PlaceHolderKey)) != *(algorithm.S.(*PlaceHolderKey)) {
		t.Error("non equal signers")
	}
}

func TestVerifyingKeyMarshaling(t *testing.T) {
	verifier := GeneratePlaceHolderKey().GetVerifier()

	newVerifier := VerifyingKey{}

	if err := protocol.Decode(protocol.Encode(&verifier), &newVerifier); err != nil {
		t.Error(err)
		return
	}
	if newVerifier.Type != verifier.Type {
		t.Errorf("expected %v, actual: %v", verifier.Type, newVerifier.Type)
		return
	}

	if *(newVerifier.V.(*PlaceHolderPublicKey)) != *(verifier.V.(*PlaceHolderPublicKey)) {
		t.Error("non equal Verifiers")
	}
}
