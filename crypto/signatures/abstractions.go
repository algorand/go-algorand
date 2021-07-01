package signatures

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/msgp/msgp"
)

type SignerKey interface {
	Sign(crypto.Hashable) crypto.Signature
}

type VerifierKey interface {
	Verify(crypto.Hashable, crypto.Signature) bool
	msgp.Marshaler
}

// Key serves as a sk+pk key pair, with capabilities of marshaling its public key.
type Key interface {
	SignerKey
	VerifierKey
}
