package crypto

import (
	"github.com/algorand/msgp/msgp"
)

type algorithmType uint64

const placeHolderType algorithmType = 1 + iota

// SignatureAlgorithm holds a Signer, and the type of algorithm the Signer conforms to.
// Signer can output a Verifier
type SignatureAlgorithm struct {
	_ msgp.Marshaler   // allows msgpack to pack the struct
	_ msgp.Unmarshaler //

	Type algorithmType
	S    Signer
}

type VerifyingKey struct {
	_ msgp.Marshaler   // allows msgpack to pack the struct
	_ msgp.Unmarshaler //

	Type algorithmType
	V    Verifier
}

type Signer interface {
	Sign(message Hashable) Signature // TODO ask - why they didn't did a slice
	SignBytes(message []byte) Signature
	GetVerifier() VerifyingKey
}

type Verifier interface {
	Verify(message Hashable, sig Signature) bool
	VerifyBytes(message []byte, sig Signature) bool
}

func GeneratePlaceHolderKey() *PlaceHolderKey {
	var seed Seed
	SystemRNG.RandBytes(seed[:])
	return &PlaceHolderKey{
		SignatureSecrets: *GenerateSignatureSecrets(seed),
	}
}

type PlaceHolderKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SignatureSecrets `codec:"sec"`
}

type PlaceHolderPublicKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	SignatureVerifier
}

func (p *PlaceHolderKey) GetVerifier() VerifyingKey {
	return VerifyingKey{
		V: &PlaceHolderPublicKey{
			SignatureVerifier: p.SignatureVerifier,
		},
		Type: placeHolderType,
	}
}

func (p *PlaceHolderPublicKey) Verify(message Hashable, sig Signature) bool {
	return p.SignatureVerifier.Verify(message, sig)
}

func (p *PlaceHolderPublicKey) VerifyBytes(message []byte, sig Signature) bool {
	return p.SignatureVerifier.VerifyBytes(message, sig)
}

func (p *PlaceHolderKey) Sign(message Hashable) Signature {
	return p.SignatureSecrets.Sign(message)
}

func (p *PlaceHolderKey) SignBytes(message []byte) Signature {
	return p.SignatureSecrets.SignBytes(message)
}

//specialized marshaling:

func (z *SignatureAlgorithm) Msgsize() (s int) {
	s = 1 + 5 + msgp.Uint64Size + 7
	if z.S == nil {
		return
	}
	switch z.Type {
	case placeHolderType:
		s += (*z).S.(*PlaceHolderKey).Msgsize()
	default:
		s += 0
	}
	return
}

func (z *SignatureAlgorithm) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize()) // adding more capacity to the bytes
	o = msgp.AppendUint64(o, uint64((*z).Type))

	if z.S == nil {
		return
	}
	o = append(o)
	switch z.Type {
	case placeHolderType:
		o = (*z).S.(*PlaceHolderKey).MarshalMsg(o)
	default:
		return nil // error
	}
	return
}

func (_ *SignatureAlgorithm) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*SignatureAlgorithm)
	return ok
}

func (z *SignatureAlgorithm) UnmarshalMsg(bts []byte) (o []byte, err error) {
	u, o, err := msgp.ReadUint64Bytes(bts)
	if err != nil {
		return
	}
	z.Type = algorithmType(u)
	switch u {
	case uint64(placeHolderType):
		z.S = new(PlaceHolderKey)
		o, err = z.S.(*PlaceHolderKey).UnmarshalMsg(o)
		if err != nil {
			return nil, err
		}

		return
	default:

	}
	return nil, msgp.TypeError{}
}

func (z *SignatureAlgorithm) MsgIsZero() bool {
	return ((*z).S == nil) && ((*z).Type == 0)
}

func (_ *SignatureAlgorithm) CanMarshalMsg(z interface{}) bool {
	_, ok := z.(*SignatureAlgorithm)
	return ok
}

func (z *VerifyingKey) Msgsize() (s int) {
	s = 1 + 5 + msgp.Uint64Size + 7
	if z.V == nil {
		return
	}
	switch z.Type {
	case placeHolderType:
		s += (*z).V.(*PlaceHolderPublicKey).Msgsize()
	default:
		s += 0
	}
	return
}

func (z *VerifyingKey) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize()) // adding more capacity to the bytes
	o = msgp.AppendUint64(o, uint64((*z).Type))
	if z.V == nil {
		return
	}
	switch z.Type {
	case placeHolderType:
		o = (*z).V.(*PlaceHolderPublicKey).MarshalMsg(o)
	default:
		return nil // error
	}
	return
}

func (_ *VerifyingKey) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*VerifyingKey)
	return ok
}

func (z *VerifyingKey) UnmarshalMsg(bts []byte) (o []byte, err error) {
	u, o, err := msgp.ReadUint64Bytes(bts)
	if err != nil {
		return
	}
	z.Type = algorithmType(u)
	switch u {
	case uint64(placeHolderType):
		v := new(PlaceHolderPublicKey)
		o, err = v.UnmarshalMsg(o)
		if err != nil {
			return nil, err
		}
		z.V = v
		return
	default:

	}
	return nil, msgp.TypeError{}
}

func (z *VerifyingKey) MsgIsZero() bool {
	return ((*z).V == nil) && ((*z).Type == 0)
}

func (_ *VerifyingKey) CanMarshalMsg(z interface{}) bool {
	_, ok := z.(*VerifyingKey)
	return ok
}
