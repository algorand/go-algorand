package crypto

type AlgorithmType uint64

const PlaceHolderType AlgorithmType = 1 + iota

type Signer interface {
	Sign(message Hashable) Signature
	SignBytes(message []byte) Signature
	GetVerifier() VerifyingKey
}

type Verifier interface {
	Verify(message Hashable, sig Signature) bool
	VerifyBytes(message []byte, sig Signature) bool
}

// SignatureAlgorithm holds a Signer, and the type of algorithm the Signer conforms to.
// to add a key - verify that PackedSignatureAlgorithm's function (getSigner) returns your key.
type SignatureAlgorithm struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType            `codec:"sigType"`
	Pack PackedSignatureAlgorithm `codec:"keys"`

	s Signer
}

type VerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType      `codec:"verType"`
	Pack PackedVerifyingKey `codec:"pubKeys"`

	v Verifier
}

func (s *SignatureAlgorithm) Sign(message Hashable) Signature {
	return s.getSigner().Sign(message)
}

func (s *SignatureAlgorithm) SignBytes(message []byte) Signature {
	return s.getSigner().SignBytes(message)
}

func (s *SignatureAlgorithm) GetVerifier() VerifyingKey {
	return s.getSigner().GetVerifier()
}

func (s *SignatureAlgorithm) getSigner() Signer {
	if s.s == nil {
		s.s = s.Pack.getSigner(s.Type)
	}
	return s.s
}

func (v *VerifyingKey) Verify(message Hashable, sig Signature) bool {
	return v.getVerifier().Verify(message, sig)
}

func (v *VerifyingKey) VerifyBytes(message []byte, sig Signature) bool {
	return v.getVerifier().VerifyBytes(message, sig)
}

func (v *VerifyingKey) setup() {
	v.v = v.Pack.getVerifier(v.Type)
}

func (v *VerifyingKey) getVerifier() Verifier {
	if v.v == nil {
		v.v = v.Pack.getVerifier(v.Type)
	}
	return v.v
}

type PackedVerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PlaceHolderPublicKey PlaceHolderPublicKey `codec:"placeholder"`
}

func (p *PackedVerifyingKey) getVerifier(t AlgorithmType) Verifier {
	switch t {
	case PlaceHolderType:
		return &p.PlaceHolderPublicKey
	default:
		panic("unknown type")
	}
}

// PackedSignatureAlgorithm used to marshal signature algorithm
type PackedSignatureAlgorithm struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PlaceHolderKey PlaceHolderKey `codec:"placeholderkey"`
}

func (p *PackedSignatureAlgorithm) getSigner(t AlgorithmType) Signer {
	switch t {
	case PlaceHolderType:
		return &p.PlaceHolderKey
	default:
		panic("unknown type")
	}
}

func NewSignerFromSeed(seed Seed, t AlgorithmType) *SignatureAlgorithm {
	var p PackedSignatureAlgorithm
	switch t {
	case 0:
		key := GeneratePlaceHolderKey(seed)
		p = PackedSignatureAlgorithm{
			PlaceHolderKey: *key,
		}
	}
	return &SignatureAlgorithm{
		Type: t,
		Pack: p,
	}
}

func NewSigner(t AlgorithmType) *SignatureAlgorithm {
	var seed Seed
	SystemRNG.RandBytes(seed[:])
	return NewSignerFromSeed(seed, t)
}

func NewVerifyingKey(t AlgorithmType, v Verifier) VerifyingKey {
	vKey := VerifyingKey{
		Type: t,
		v:    v,
		Pack: PackedVerifyingKey{},
	}
	switch t {
	case PlaceHolderType:
		vKey.Pack.PlaceHolderPublicKey = *(v.(*PlaceHolderPublicKey))
	default:
		panic("unknown type")
	}
	return vKey
}
