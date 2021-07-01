package signatures

import (
	"github.com/algorand/go-algorand/crypto"
)

type ed25519Key struct {
	*crypto.SignatureSecrets
}

func (k *ed25519Key) Unmarshal(bytes []byte) {
	panic("implement me")
}

func newEd25519Key(seed crypto.Seed) Key {
	return &ed25519Key{
		SignatureSecrets: crypto.GenerateSignatureSecrets(seed),
	}
}

// TODO: consider exporting the original function from the crypto.utils file! (ask idan about his thoughts)
func hashRep(hashable crypto.Hashable) []byte {
	hashid, data := hashable.ToBeHashed()
	return append([]byte(hashid), data...)
}

func (k *ed25519Key) Sign(hashable crypto.Hashable) crypto.Signature {
	return k.SignBytes(hashRep(hashable))
}

func (k *ed25519Key) Verify(hashable crypto.Hashable, signature crypto.Signature) bool {
	return k.VerifyBytes(hashRep(hashable), signature)
}
