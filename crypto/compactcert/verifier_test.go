package compactcert

import (
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifyRevelForEachPosition(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	cert, param, partCom, numPart := generateCertForTesting(a)

	verifier := MkVerifier(param, partCom)
	err := verifier.Verify(cert)
	a.NoError(err)

	for i := uint64(0); i < numPart; i++ {
		_, ok := cert.Reveals[i]
		if !ok {
			cert.PositionsToReveal[0] = i
			break
		}
	}

	verifier = MkVerifier(param, partCom)
	err = verifier.Verify(cert)
	a.ErrorIs(err, ErrNoRevealInPos)

}

func TestVerifyWrongCoinSlot(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	cert, param, partCom, _ := generateCertForTesting(a)

	verifier := MkVerifier(param, partCom)
	err := verifier.Verify(cert)
	a.NoError(err)

	swap := cert.PositionsToReveal[1]
	cert.PositionsToReveal[1] = cert.PositionsToReveal[0]
	cert.PositionsToReveal[0] = swap

	verifier = MkVerifier(param, partCom)
	err = verifier.Verify(cert)
	a.ErrorIs(err, ErrCoinNotInRange)
}

func TestVerifyBadSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	cert, param, partCom, _ := generateCertForTesting(a)

	verifier := MkVerifier(param, partCom)
	err := verifier.Verify(cert)
	a.NoError(err)

	rev := cert.Reveals[cert.PositionsToReveal[0]]
	rev.SigSlot.Sig.Signature[10] += 1

	verifier = MkVerifier(param, partCom)
	err = verifier.Verify(cert)
	a.ErrorIs(err, merklesignature.ErrSignatureSchemeVerificationFailed)
}
