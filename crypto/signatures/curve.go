package signatures

//type MasterDerivationKey [masterDerivationKeyLenBytes]byte

//// PrivateKey is an exported ed25519PrivateKey
//type PrivateKey ed25519PrivateKey

//// PublicKey is an exported ed25519PublicKey
//type PublicKey ed25519PublicKey

//// A Signature is a cryptographic signature. It proves that a message was
//// produced by a holder of a cryptographic secret.
//type Signature ed25519Signature

//// BlankSignature is an empty signature structure, containing nothing but zeroes
//var BlankSignature = Signature{}

//// Blank tests to see if the given signature contains only zeros
//func (s *Signature) Blank() bool {
//	return (*s) == BlankSignature
//}

//// A SignatureVerifier is used to identify the holder of SignatureSecrets
//// and verify the authenticity of Signatures.
//type SignatureVerifier = PublicKey

//// SignatureSecrets are used by an entity to produce unforgeable signatures over
//// a message.
//type SignatureSecrets struct {
//	_struct struct{} `codec:""`
//
//	SignatureVerifier
//	SK ed25519PrivateKey
//}

//// GenerateSignatureSecrets creates SignatureSecrets from a source of entropy.
//func GenerateSignatureSecrets(seed Seed) *SignatureSecrets {
//	pk0, sk := ed25519GenerateKeySeed(ed25519Seed(seed))
//	pk := SignatureVerifier(pk0)
//	cryptoGenSigSecretsTotal.Inc(map[string]string{})
//	return &SignatureSecrets{SignatureVerifier: pk, SK: sk}
//}

//// Sign produces a cryptographic Signature of a Hashable message, given
//// cryptographic secrets.
//func (s *SignatureSecrets) Sign(message Hashable) Signature {
//	cryptoSigSecretsSignTotal.Inc(map[string]string{})
//	return s.SignBytes(hashRep(message))
//}

//// SignBytes signs a message directly, without first hashing.
//// Caller is responsible for domain separation.
//func (s *SignatureSecrets) SignBytes(message []byte) Signature {
//	cryptoSigSecretsSignBytesTotal.Inc(map[string]string{})
//	return Signature(ed25519Sign(ed25519PrivateKey(s.SK), message))
//}

//// Verify verifies that some holder of a cryptographic secret authentically
//// signed a Hashable message.
////
//// It returns true if this is the case; otherwise, it returns false.
////
//func (v SignatureVerifier) Verify(message Hashable, sig Signature) bool {
//	cryptoSigSecretsVerifyTotal.Inc(map[string]string{})
//	return ed25519Verify(ed25519PublicKey(v), hashRep(message), ed25519Signature(sig))
//}

//// VerifyBytes verifies a signature, where the message is not hashed first.
//// Caller is responsible for domain separation.
//// If the message is a Hashable, Verify() can be used instead.
//func (v SignatureVerifier) VerifyBytes(message []byte, sig Signature) bool {
//	cryptoSigSecretsVerifyBytesTotal.Inc(map[string]string{})
//	return ed25519Verify(ed25519PublicKey(v), message, ed25519Signature(sig))
//}
