package crypto

import "fmt"

// AlgorithmType enum type for signing algorithms
type AlgorithmType uint64

// all AlgorithmType enums
const (
	PlaceHolderType AlgorithmType = 1 + iota
)

// ByteSignature is a cryptographic signature represented by bytes.
type ByteSignature []byte

// Signer interface represents the possible things that can be done with a signing key.
// outputs Sign, SignBytes which are self explanatory and GetVerifier which is a representation of a public key.
type Signer interface {
	Sign(message Hashable) ByteSignature
	SignBytes(message []byte) ByteSignature
	GetVerifier() VerifyingKey
}

// ErrBadSignature represents a bad signature
var ErrBadSignature = fmt.Errorf("invalid signature")

// Verifier interface represent a public key of a signature scheme.
// Verifier returns error for bad signature/ other issues while verifying a signature, or nil for correct signature -
// that is, returns: complain or no complain.
type Verifier interface {
	Verify(message Hashable, sig ByteSignature) error
	VerifyBytes(message []byte, sig ByteSignature) error
}

// SignatureAlgorithm holds a Signer, and the type of algorithm the Signer conforms to.
// to add a key - verify that PackedSignatureAlgorithm's function (getSigner) returns your key.
type SignatureAlgorithm struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType            `codec:"sigType"`
	Pack PackedSignatureAlgorithm `codec:"keys"`
}

// VerifyingKey is the correct way to interact with a Verifier. It implements the interface,
// but allows for correct marshling and unmarshling of itself.
type VerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType      `codec:"verType"`
	Pack PackedVerifyingKey `codec:"pubKeys"`
}

// Sign - Signs a Hashable message
func (s *SignatureAlgorithm) Sign(message Hashable) []byte {
	return s.Pack.getSigner(s.Type).Sign(message)
}

// SignBytes - Signs a a slice of bytes
func (s *SignatureAlgorithm) SignBytes(message []byte) []byte {
	return s.Pack.getSigner(s.Type).SignBytes(message)
}

// GetVerifier outputs a representation of a public key. that implements Verifier
func (s *SignatureAlgorithm) GetVerifier() VerifyingKey {
	return s.Pack.getSigner(s.Type).GetVerifier()
}

// Verify that a signature match to a specific message
func (v *VerifyingKey) Verify(message Hashable, sig []byte) error {
	return v.Pack.getVerifier(v.Type).Verify(message, sig)
}

// VerifyBytes checks that a signature match to a specific byte message
func (v *VerifyingKey) VerifyBytes(message []byte, sig []byte) error {
	return v.Pack.getVerifier(v.Type).VerifyBytes(message, sig)
}

// PackedVerifyingKey is a key store. Allows for easy marshal/unmarshal.
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

// NewSignerFromSeed Generates a new signer from a specific Seed
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

// NewSigner receives a type of signing algorithm and generates keys.
func NewSigner(t AlgorithmType) *SignatureAlgorithm {
	var seed Seed
	SystemRNG.RandBytes(seed[:])
	return NewSignerFromSeed(seed, t)
}

func newVerifyingKey(t AlgorithmType, v Verifier) VerifyingKey {
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
