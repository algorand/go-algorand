package crypto

func GeneratePlaceHolderKey(seed Seed) *PlaceHolderKey {
	return &PlaceHolderKey{
		Sec: *GenerateSignatureSecrets(seed),
	}
}

type PlaceHolderKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sec SignatureSecrets `codec:"sec"`
}

type PlaceHolderPublicKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SignatureVerifier `codec:"sigVerifier"`
}

func (p *PlaceHolderKey) Sign(message Hashable) Signature {
	return p.Sec.Sign(message)
}

func (p *PlaceHolderKey) SignBytes(message []byte) Signature {
	return p.Sec.SignBytes(message)
}

func (p *PlaceHolderKey) GetVerifier() VerifyingKey {
	return NewVerifyingKey(PlaceHolderType, &PlaceHolderPublicKey{SignatureVerifier: p.Sec.SignatureVerifier})
}

func (p *PlaceHolderPublicKey) Verify(message Hashable, sig Signature) bool {
	return p.SignatureVerifier.Verify(message, sig)
}

func (p *PlaceHolderPublicKey) VerifyBytes(message []byte, sig Signature) bool {
	return p.SignatureVerifier.VerifyBytes(message, sig)
}
