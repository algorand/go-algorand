package msgp

import (
	"fmt"
	"math"
)

const (
	// Complex64Extension is the extension number used for complex64
	Complex64Extension = 3

	// Complex128Extension is the extension number used for complex128
	Complex128Extension = 4

	// TimeExtension is the extension number used for time.Time
	TimeExtension = 5
)

// our extensions live here
var extensionReg = make(map[int8]func() Extension)

// RegisterExtension registers extensions so that they
// can be initialized and returned by methods that
// decode `interface{}` values. This should only
// be called during initialization. f() should return
// a newly-initialized zero value of the extension. Keep in
// mind that extensions 3, 4, and 5 are reserved for
// complex64, complex128, and time.Time, respectively,
// and that MessagePack reserves extension types from -127 to -1.
//
// For example, if you wanted to register a user-defined struct:
//
//  msgp.RegisterExtension(10, func() msgp.Extension { &MyExtension{} })
//
// RegisterExtension will panic if you call it multiple times
// with the same 'typ' argument, or if you use a reserved
// type (3, 4, or 5).
func RegisterExtension(typ int8, f func() Extension) {
	switch typ {
	case Complex64Extension, Complex128Extension, TimeExtension:
		panic(fmt.Sprint("msgp: forbidden extension type:", typ))
	}
	if _, ok := extensionReg[typ]; ok {
		panic(fmt.Sprint("msgp: RegisterExtension() called with typ", typ, "more than once"))
	}
	extensionReg[typ] = f
}

// ExtensionTypeError is an error type returned
// when there is a mis-match between an extension type
// and the type encoded on the wire
type ExtensionTypeError struct {
	Got  int8
	Want int8
}

// Error implements the error interface
func (e ExtensionTypeError) Error() string {
	return fmt.Sprintf("msgp: error decoding extension: wanted type %d; got type %d", e.Want, e.Got)
}

// Resumable returns 'true' for ExtensionTypeErrors
func (e ExtensionTypeError) Resumable() bool { return true }

func errExt(got int8, wanted int8) error {
	return ExtensionTypeError{Got: got, Want: wanted}
}

// Extension is the interface fulfilled
// by types that want to define their
// own binary encoding.
type Extension interface {
	// ExtensionType should return
	// a int8 that identifies the concrete
	// type of the extension. (Types <0 are
	// officially reserved by the MessagePack
	// specifications.)
	ExtensionType() int8

	// Len should return the length
	// of the data to be encoded
	Len() int

	// MarshalBinaryTo should copy
	// the data into the supplied slice,
	// assuming that the slice has length Len()
	MarshalBinaryTo([]byte) error

	UnmarshalBinary([]byte) error
}

// RawExtension implements the Extension interface
type RawExtension struct {
	Data []byte
	Type int8
}

// ExtensionType implements Extension.ExtensionType, and returns r.Type
func (r *RawExtension) ExtensionType() int8 { return r.Type }

// Len implements Extension.Len, and returns len(r.Data)
func (r *RawExtension) Len() int { return len(r.Data) }

// MarshalBinaryTo implements Extension.MarshalBinaryTo,
// and returns a copy of r.Data
func (r *RawExtension) MarshalBinaryTo(d []byte) error {
	copy(d, r.Data)
	return nil
}

// UnmarshalBinary implements Extension.UnmarshalBinary,
// and sets r.Data to the contents of the provided slice
func (r *RawExtension) UnmarshalBinary(b []byte) error {
	if cap(r.Data) >= len(b) {
		r.Data = r.Data[0:len(b)]
	} else {
		r.Data = make([]byte, len(b))
	}
	copy(r.Data, b)
	return nil
}

// peekExtension peeks at the extension encoding type
// (must guarantee at least 1 byte in 'b')
func peekExtension(b []byte) (int8, error) {
	spec := sizes[b[0]]
	size := spec.size
	if spec.typ != ExtensionType {
		return 0, badPrefix(ExtensionType, b[0])
	}
	if len(b) < int(size) {
		return 0, ErrShortBytes
	}
	// for fixed extensions,
	// the type information is in
	// the second byte
	if spec.extra == constsize {
		return int8(b[1]), nil
	}
	// otherwise, it's in the last
	// part of the prefix
	return int8(b[size-1]), nil
}

// AppendExtension appends a MessagePack extension to the provided slice
func AppendExtension(b []byte, e Extension) ([]byte, error) {
	l := e.Len()
	var o []byte
	var n int
	switch l {
	case 0:
		o, n = ensure(b, 3)
		o[n] = mext8
		o[n+1] = 0
		o[n+2] = byte(e.ExtensionType())
		return o[:n+3], nil
	case 1:
		o, n = ensure(b, 3)
		o[n] = mfixext1
		o[n+1] = byte(e.ExtensionType())
		n += 2
	case 2:
		o, n = ensure(b, 4)
		o[n] = mfixext2
		o[n+1] = byte(e.ExtensionType())
		n += 2
	case 4:
		o, n = ensure(b, 6)
		o[n] = mfixext4
		o[n+1] = byte(e.ExtensionType())
		n += 2
	case 8:
		o, n = ensure(b, 10)
		o[n] = mfixext8
		o[n+1] = byte(e.ExtensionType())
		n += 2
	case 16:
		o, n = ensure(b, 18)
		o[n] = mfixext16
		o[n+1] = byte(e.ExtensionType())
		n += 2
	default:
		switch {
		case l < math.MaxUint8:
			o, n = ensure(b, l+3)
			o[n] = mext8
			o[n+1] = byte(uint8(l))
			o[n+2] = byte(e.ExtensionType())
			n += 3
		case l < math.MaxUint16:
			o, n = ensure(b, l+4)
			o[n] = mext16
			big.PutUint16(o[n+1:], uint16(l))
			o[n+3] = byte(e.ExtensionType())
			n += 4
		default:
			o, n = ensure(b, l+6)
			o[n] = mext32
			big.PutUint32(o[n+1:], uint32(l))
			o[n+5] = byte(e.ExtensionType())
			n += 6
		}
	}
	return o, e.MarshalBinaryTo(o[n:])
}

// ReadExtensionBytes reads an extension from 'b' into 'e'
// and returns any remaining bytes.
// Possible errors:
// - ErrShortBytes ('b' not long enough)
// - ExtensionTypeError{} (wire type not the same as e.Type())
// - TypeError{} (next object not an extension)
// - InvalidPrefixError
// - An umarshal error returned from e.UnmarshalBinary
func ReadExtensionBytes(b []byte, e Extension) ([]byte, error) {
	l := len(b)
	if l < 3 {
		return b, ErrShortBytes
	}
	lead := b[0]
	var (
		sz  int // size of 'data'
		off int // offset of 'data'
		typ int8
	)
	switch lead {
	case mfixext1:
		typ = int8(b[1])
		sz = 1
		off = 2
	case mfixext2:
		typ = int8(b[1])
		sz = 2
		off = 2
	case mfixext4:
		typ = int8(b[1])
		sz = 4
		off = 2
	case mfixext8:
		typ = int8(b[1])
		sz = 8
		off = 2
	case mfixext16:
		typ = int8(b[1])
		sz = 16
		off = 2
	case mext8:
		sz = int(uint8(b[1]))
		typ = int8(b[2])
		off = 3
		if sz == 0 {
			return b[3:], e.UnmarshalBinary(b[3:3])
		}
	case mext16:
		if l < 4 {
			return b, ErrShortBytes
		}
		sz = int(big.Uint16(b[1:]))
		typ = int8(b[3])
		off = 4
	case mext32:
		if l < 6 {
			return b, ErrShortBytes
		}
		var err error
		sz, err = u32int(big.Uint32(b[1:]))
		if err != nil {
			return b, err
		}
		typ = int8(b[5])
		off = 6
	default:
		return b, badPrefix(ExtensionType, lead)
	}

	if typ != e.ExtensionType() {
		return b, errExt(typ, e.ExtensionType())
	}

	// the data of the extension starts
	// at 'off' and is 'sz' bytes long
	if len(b[off:]) < sz {
		return b, ErrShortBytes
	}
	tot := off + sz
	return b[tot:], e.UnmarshalBinary(b[off:tot])
}
