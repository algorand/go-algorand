package merklekeystore

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
)

type verifier struct {
	root       crypto.Digest `codec:"r"`
	startRound uint64
	endRound   uint64
}

func (v *verifier) verify(obj crypto.Hashable, sig Signature) error {
	isInTree := merklearray.Verify(v.root, map[uint64]crypto.Digest{sig.pos: crypto.HashObj(sig.VerifyingKey)}, sig.Proof)
	if isInTree != nil {
		return isInTree
	}
	return sig.VerifyingKey.GetVerifier().Verify(obj, sig.ByteSignature)
}
