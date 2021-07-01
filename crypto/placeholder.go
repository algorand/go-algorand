package crypto

type Signer interface {
	Sign(message Hashable) []byte // TODO ask - why they didn't did a slice
	SignBytes(message []byte) []byte
	GetVerifier() Verifier
}

type Verifier interface {
	Verify(message Hashable, sig []byte) bool
	VerifyBytes(message []byte, sig []byte) bool
}

func GeneratePlaceHolderKey() *PlaceHolderKey {
	var seed Seed
	SystemRNG.RandBytes(seed[:])
	return &PlaceHolderKey{
		secret: GenerateSignatureSecrets(seed),
	}
}

type PlaceHolderKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	secret *SignatureSecrets `codec:"sec"`
}

type PlaceHolderPublicKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	*SignatureVerifier
}

func (p *PlaceHolderKey) GetVerifier() PlaceHolderPublicKey {
	return PlaceHolderPublicKey{
		SignatureVerifier: &p.secret.SignatureVerifier,
	}
}

func (p *PlaceHolderKey) Verify(message Hashable, sig Signature) bool {
	return p.secret.Verify(message, sig)
}

func (p *PlaceHolderKey) VerifyBytes(message []byte, sig Signature) bool {
	return p.secret.VerifyBytes(message, sig)
}

func (p *PlaceHolderKey) Sign(message Hashable) Signature {
	return p.secret.Sign(message)
}

func (p *PlaceHolderKey) SignBytes(message []byte) Signature {
	return p.secret.SignBytes(message)
}
