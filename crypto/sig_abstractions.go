package crypto

type AlgorithmType uint64

const PlaceHolderType AlgorithmType = 1 + iota

type ByteSignature []byte

type Signer interface {
	Sign(message Hashable) ByteSignature
	SignBytes(message []byte) ByteSignature
	GetVerifier() VerifyingKey
}

type Verifier interface {
	Verify(message Hashable, sig ByteSignature) bool
	VerifyBytes(message []byte, sig ByteSignature) bool
}

// SignatureAlgorithm holds a Signer, and the type of algorithm the Signer conforms to.
// to add a key - verify that PackedSignatureAlgorithm's function (getSigner) returns your key.
type SignatureAlgorithm struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType            `codec:"sigType"`
	Pack PackedSignatureAlgorithm `codec:"keys"`
}

type VerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType      `codec:"verType"`
	Pack PackedVerifyingKey `codec:"pubKeys"`
}

func (s *SignatureAlgorithm) Sign(message Hashable) []byte {
	return s.Pack.getSigner(s.Type).Sign(message)
}

func (s *SignatureAlgorithm) SignBytes(message []byte) []byte {
	return s.Pack.getSigner(s.Type).SignBytes(message)
}

func (s *SignatureAlgorithm) GetVerifier() VerifyingKey {
	return s.Pack.getSigner(s.Type).GetVerifier()
}

func (v *VerifyingKey) Verify(message Hashable, sig []byte) bool {
	return v.Pack.getVerifier(v.Type).Verify(message, sig)
}

func (v *VerifyingKey) VerifyBytes(message []byte, sig []byte) bool {
	return v.Pack.getVerifier(v.Type).VerifyBytes(message, sig)
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
	case PlaceHolderType:
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
