package stateproof

import (
	"github.com/algorand/go-algorand/crypto"
	cc "github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/protocol"
)

// Message represents the message to be certified.
type Message struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Payload []byte   `codec:"p"`
}

// ToBeHashed returns the bytes of the message.
func (m Message) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.CompactCertMessage, m.Payload
}

// IntoStateProofMessageHash returns a hashed representation fitting the compact certificate messages.
func (m Message) IntoStateProofMessageHash() cc.StateProofMessageHash {
	digest := crypto.GenericHashObj(crypto.HashFactory{HashType: cc.StateProofMessageHashType}.NewHash(), m)
	result := cc.StateProofMessageHash{}
	copy(result[:], digest)
	return result
}
