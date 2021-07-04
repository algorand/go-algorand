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

func (p *PlaceHolderKey) Sign(message Hashable) ByteSignature {
	sig := p.Sec.Sign(message)
	return sig[:]
}

func (p *PlaceHolderKey) SignBytes(message []byte) ByteSignature {
	sig := p.Sec.SignBytes(message)
	return sig[:]
}

func (p *PlaceHolderKey) GetVerifier() VerifyingKey {
	return NewVerifyingKey(PlaceHolderType, &PlaceHolderPublicKey{SignatureVerifier: p.Sec.SignatureVerifier})
}

func (p *PlaceHolderPublicKey) Verify(message Hashable, sig ByteSignature) bool {
	var scopy Signature
	copy(scopy[:], sig)
	return p.SignatureVerifier.Verify(message, scopy)
}

func (p *PlaceHolderPublicKey) VerifyBytes(message []byte, sig ByteSignature) bool {
	var scopy Signature
	copy(scopy[:], sig)
	return p.SignatureVerifier.VerifyBytes(message, scopy)
}
