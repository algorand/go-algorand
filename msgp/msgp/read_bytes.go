package msgp

import (
	"encoding/binary"
	"math"
	"time"
)

var big = binary.BigEndian

// NextType returns the type of the next
// object in the slice. If the length
// of the input is zero, it returns
// InvalidType.
func NextType(b []byte) Type {
	if len(b) == 0 {
		return InvalidType
	}
	spec := sizes[b[0]]
	t := spec.typ
	if t == ExtensionType && len(b) > int(spec.size) {
		var tp int8
		if spec.extra == constsize {
			tp = int8(b[1])
		} else {
			tp = int8(b[spec.size-1])
		}
		switch tp {
		case TimeExtension:
			return TimeType
		case Complex128Extension:
			return Complex128Type
		case Complex64Extension:
			return Complex64Type
		default:
			return ExtensionType
		}
	}
	return t
}

// IsNil returns true if len(b)>0 and
// the leading byte is a 'nil' MessagePack
// byte; false otherwise
func IsNil(b []byte) bool {
	if len(b) != 0 && b[0] == mnil {
		return true
	}
	return false
}

// Raw is raw MessagePack.
// Raw allows you to read and write
// data without interpreting its contents.
type Raw []byte

// CanMarshalMsg returns true if the z interface is a Raw object ( part of the Marshaler interface )
func (Raw) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(Raw)
	if !ok {
		_, ok = (z).(*Raw)
	}
	return ok
}

// MarshalMsg implements msgp.Marshaler.
// It appends the raw contents of 'raw'
// to the provided byte slice. If 'raw'
// is 0 bytes, 'nil' will be appended instead.
func (r Raw) MarshalMsg(b []byte) []byte {
	i := len(r)
	if i == 0 {
		return AppendNil(b)
	}
	o, l := ensure(b, i)
	copy(o[l:], []byte(r))
	return o
}

// CanUnmarshalMsg returns true if the z interface is a Raw object ( part of the Unmarshaler interface )
func (*Raw) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*Raw)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler.
// It sets the contents of *Raw to be the next
// object in the provided byte slice.
func (r *Raw) UnmarshalMsg(b []byte) ([]byte, error) {
	return r.UnmarshalMsgWithState(b, DefaultUnmarshalState)
}

// UnmarshalMsg implements msgp.Unmarshaler.
// It sets the contents of *Raw to be the next
// object in the provided byte slice.
func (r *Raw) UnmarshalMsgWithState(b []byte, st UnmarshalState) ([]byte, error) {
	if st.Depth == 0 {
		return nil, ErrMaxDepthExceeded{}
	}
	l := len(b)
	out, err := Skip(b)
	if err != nil {
		return b, err
	}
	rlen := l - len(out)
	if IsNil(b[:rlen]) {
		rlen = 0
	}
	if cap(*r) < rlen {
		*r = make(Raw, rlen)
	} else {
		*r = (*r)[0:rlen]
	}
	copy(*r, b[:rlen])
	return out, nil
}

// Msgsize implements msgp.Sizer
func (r Raw) Msgsize() int {
	l := len(r)
	if l == 0 {
		return 1 // for 'nil'
	}
	return l
}

// MsgIsZero returns whether this is a zero value
func (r *Raw) MsgIsZero() bool {
	return len(*r) == 0
}

// ReadMapHeaderBytes reads a map header size
// from 'b' and returns the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a map)
func ReadMapHeaderBytes(b []byte) (sz int, isnil bool, o []byte, err error) {
	l := len(b)
	if l < 1 {
		err = ErrShortBytes
		return
	}

	lead := b[0]
	if isfixmap(lead) {
		sz = int(rfixmap(lead))
		o = b[1:]
		return
	}

	switch lead {
	// go-codec compatibility: mnil decodes as a nil map / empty struct
	case mnil:
		sz = 0
		o = b[1:]
		isnil = true
		return

	case mmap16:
		if l < 3 {
			err = ErrShortBytes
			return
		}
		sz = int(big.Uint16(b[1:]))
		o = b[3:]
		return

	case mmap32:
		if l < 5 {
			err = ErrShortBytes
			return
		}
		sz, err = u32int(big.Uint32(b[1:]))
		if err != nil {
			return
		}
		o = b[5:]
		return

	default:
		o = b
		err = badPrefix(MapType, lead)
		return
	}
}

// ReadMapKeyZC attempts to read a map key
// from 'b' and returns the key bytes and the remaining bytes
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a str or bin)
func ReadMapKeyZC(b []byte) ([]byte, []byte, error) {
	o, x, err := ReadStringZC(b)
	if err != nil {
		if tperr, ok := err.(TypeError); ok && tperr.Encoded == BinType {
			return ReadBytesZC(b)
		}
		return nil, b, err
	}
	return o, x, nil
}

// ReadArrayHeaderBytes attempts to read
// the array header size off of 'b' and return
// the size and remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not an array)
func ReadArrayHeaderBytes(b []byte) (sz int, isnil bool, o []byte, err error) {
	return readArrayHeaderBytes(b, true)
}

func readArrayHeaderBytes(b []byte, flattenMap bool) (sz int, isnil bool, o []byte, err error) {
	if len(b) < 1 {
		return 0, false, nil, ErrShortBytes
	}
	lead := b[0]
	if isfixarray(lead) {
		sz = int(rfixarray(lead))
		o = b[1:]
		return
	}

	// go-codec compat: map can be decoded as an array, by alternating
	// the map keys and values in the decoded array.
	if flattenMap && isfixmap(lead) {
		sz = 2 * int(rfixmap(lead))
		o = b[1:]
		return
	}

	switch lead {
	case mnil:
		// go-codec compat: nil decodes as an empty array (nil for slice)
		sz = 0
		o = b[1:]
		isnil = true
		return

	case marray16:
		if len(b) < 3 {
			err = ErrShortBytes
			return
		}
		sz = int(big.Uint16(b[1:]))
		o = b[3:]
		return

	case marray32:
		if len(b) < 5 {
			err = ErrShortBytes
			return
		}
		sz, err = u32int(big.Uint32(b[1:]))
		if err != nil {
			return
		}
		o = b[5:]
		return

	// go-codec compat: map can be decoded as an array, by alternating
	// the map keys and values in the decoded array.
	case mmap16:
		if flattenMap {
			if len(b) < 3 {
				err = ErrShortBytes
				return
			}
			sz = 2 * int(big.Uint16(b[1:]))
			o = b[3:]
			return
		}

	case mmap32:
		if flattenMap {
			if len(b) < 5 {
				err = ErrShortBytes
				return
			}
			u64sz := 2 * uint64(big.Uint32(b[1:]))
			sz, err = u64int(u64sz)
			if err != nil {
				return
			}
			o = b[5:]
			return
		}
	}

	o = b
	err = badPrefix(ArrayType, lead)
	return
}

// ReadNilBytes tries to read a "nil" byte
// off of 'b' and return the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a 'nil')
// - InvalidPrefixError
func ReadNilBytes(b []byte) ([]byte, error) {
	if len(b) < 1 {
		return nil, ErrShortBytes
	}
	if b[0] != mnil {
		return b, badPrefix(NilType, b[0])
	}
	return b[1:], nil
}

// ReadFloat64Bytes tries to read a float64
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a float64)
func ReadFloat64Bytes(b []byte) (f float64, o []byte, err error) {
	if len(b) < 9 {
		if len(b) >= 5 && b[0] == mfloat32 {
			var tf float32
			tf, o, err = ReadFloat32Bytes(b)
			f = float64(tf)
			return
		}
		if b[0] == mnil {
			o = b[1:]
			return
		}
		err = ErrShortBytes
		return
	}

	if b[0] != mfloat64 {
		if b[0] == mfloat32 {
			var tf float32
			tf, o, err = ReadFloat32Bytes(b)
			f = float64(tf)
			return
		}
		err = badPrefix(Float64Type, b[0])
		return
	}

	f = math.Float64frombits(getMuint64(b))
	o = b[9:]
	return
}

// ReadFloat32Bytes tries to read a float64
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a float32)
func ReadFloat32Bytes(b []byte) (f float32, o []byte, err error) {
	if len(b) < 1 {
		err = ErrShortBytes
		return
	}

	if b[0] == mnil {
		o = b[1:]
		return
	}

	if b[0] != mfloat32 {
		err = TypeError{Method: Float32Type, Encoded: getType(b[0])}
		return
	}

	if len(b) < 5 {
		err = ErrShortBytes
		return
	}

	f = math.Float32frombits(getMuint32(b))
	o = b[5:]
	return
}

// ReadBoolBytes tries to read a float64
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a bool)
func ReadBoolBytes(b []byte) (bool, []byte, error) {
	if len(b) < 1 {
		return false, b, ErrShortBytes
	}
	switch b[0] {
	case mtrue:
		return true, b[1:], nil
	case mfalse:
		return false, b[1:], nil
	case mnil:
		return false, b[1:], nil
	default:
		return false, b, badPrefix(BoolType, b[0])
	}
}

// ReadDurationBytes tries to read a time.Duration
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError (not a int)
func ReadDurationBytes(b []byte) (d time.Duration, o []byte, err error) {
	i, o, err := ReadInt64Bytes(b)
	return time.Duration(i), o, err
}

// ReadInt64Bytes tries to read an int64
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError (not a int)
func ReadInt64Bytes(b []byte) (i int64, o []byte, err error) {
	l := len(b)
	if l < 1 {
		return 0, nil, ErrShortBytes
	}

	lead := b[0]
	if isfixint(lead) {
		i = int64(rfixint(lead))
		o = b[1:]
		return
	}
	if isnfixint(lead) {
		i = int64(rnfixint(lead))
		o = b[1:]
		return
	}

	switch lead {
	case mnil:
		i = 0
		o = b[1:]
		return

	case mint8:
		if l < 2 {
			err = ErrShortBytes
			return
		}
		i = int64(getMint8(b))
		o = b[2:]
		return

	case muint8:
		if l < 2 {
			err = ErrShortBytes
			return
		}
		i = int64(getMuint8(b))
		o = b[2:]
		return

	case mint16:
		if l < 3 {
			err = ErrShortBytes
			return
		}
		i = int64(getMint16(b))
		o = b[3:]
		return

	case muint16:
		if l < 3 {
			err = ErrShortBytes
			return
		}
		i = int64(getMuint16(b))
		o = b[3:]
		return

	case mint32:
		if l < 5 {
			err = ErrShortBytes
			return
		}
		i = int64(getMint32(b))
		o = b[5:]
		return

	case muint32:
		if l < 5 {
			err = ErrShortBytes
			return
		}
		i = int64(getMuint32(b))
		o = b[5:]
		return

	case mint64:
		if l < 9 {
			err = ErrShortBytes
			return
		}
		i = int64(getMint64(b))
		o = b[9:]
		return

	case muint64:
		if l < 9 {
			err = ErrShortBytes
			return
		}
		u := getMuint64(b)
		// go-codec compat: uint64 encodings that exceed MaxInt64
		// just overflow when parsed as int64.
		//
		// if u > math.MaxInt64 {
		// 	err = UintOverflow{Value: u, FailedBitsize: 64}
		// 	return
		// }
		i = int64(u)
		o = b[9:]
		return

	default:
		err = badPrefix(IntType, lead)
		return
	}
}

// ReadInt32Bytes tries to read an int32
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a int)
// - IntOverflow{} (value doesn't fit in int32)
func ReadInt32Bytes(b []byte) (int32, []byte, error) {
	i, o, err := ReadInt64Bytes(b)
	if i > math.MaxInt32 || i < math.MinInt32 {
		return 0, o, IntOverflow{Value: i, FailedBitsize: 32}
	}
	return int32(i), o, err
}

// ReadInt16Bytes tries to read an int16
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a int)
// - IntOverflow{} (value doesn't fit in int16)
func ReadInt16Bytes(b []byte) (int16, []byte, error) {
	i, o, err := ReadInt64Bytes(b)
	if i > math.MaxInt16 || i < math.MinInt16 {
		return 0, o, IntOverflow{Value: i, FailedBitsize: 16}
	}
	return int16(i), o, err
}

// ReadInt8Bytes tries to read an int16
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a int)
// - IntOverflow{} (value doesn't fit in int8)
func ReadInt8Bytes(b []byte) (int8, []byte, error) {
	i, o, err := ReadInt64Bytes(b)
	if i > math.MaxInt8 || i < math.MinInt8 {
		return 0, o, IntOverflow{Value: i, FailedBitsize: 8}
	}
	return int8(i), o, err
}

// ReadUint64Bytes tries to read a uint64
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a uint)
func ReadUint64Bytes(b []byte) (u uint64, o []byte, err error) {
	l := len(b)
	if l < 1 {
		return 0, nil, ErrShortBytes
	}

	lead := b[0]
	if isfixint(lead) {
		u = uint64(rfixint(lead))
		o = b[1:]
		return
	}

	switch lead {
	case mnil:
		u = 0
		o = b[1:]
		return

	case mint8:
		if l < 2 {
			err = ErrShortBytes
			return
		}
		v := int64(getMint8(b))
		if v < 0 {
			err = UintBelowZero{Value: v}
			return
		}
		u = uint64(v)
		o = b[2:]
		return

	case muint8:
		if l < 2 {
			err = ErrShortBytes
			return
		}
		u = uint64(getMuint8(b))
		o = b[2:]
		return

	case mint16:
		if l < 3 {
			err = ErrShortBytes
			return
		}
		v := int64(getMint16(b))
		if v < 0 {
			err = UintBelowZero{Value: v}
			return
		}
		u = uint64(v)
		o = b[3:]
		return

	case muint16:
		if l < 3 {
			err = ErrShortBytes
			return
		}
		u = uint64(getMuint16(b))
		o = b[3:]
		return

	case mint32:
		if l < 5 {
			err = ErrShortBytes
			return
		}
		v := int64(getMint32(b))
		if v < 0 {
			err = UintBelowZero{Value: v}
			return
		}
		u = uint64(v)
		o = b[5:]
		return

	case muint32:
		if l < 5 {
			err = ErrShortBytes
			return
		}
		u = uint64(getMuint32(b))
		o = b[5:]
		return

	case mint64:
		if l < 9 {
			err = ErrShortBytes
			return
		}
		v := int64(getMint64(b))
		if v < 0 {
			err = UintBelowZero{Value: v}
			return
		}
		u = uint64(v)
		o = b[9:]
		return

	case muint64:
		if l < 9 {
			err = ErrShortBytes
			return
		}
		u = getMuint64(b)
		o = b[9:]
		return

	default:
		if isnfixint(lead) {
			err = UintBelowZero{Value: int64(rnfixint(lead))}
		} else {
			err = badPrefix(UintType, lead)
		}
		return
	}
}

// ReadUint32Bytes tries to read a uint32
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a uint)
// - UintOverflow{} (value too large for uint32)
func ReadUint32Bytes(b []byte) (uint32, []byte, error) {
	v, o, err := ReadUint64Bytes(b)
	if v > math.MaxUint32 {
		return 0, nil, UintOverflow{Value: v, FailedBitsize: 32}
	}
	return uint32(v), o, err
}

// ReadUint16Bytes tries to read a uint16
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a uint)
// - UintOverflow{} (value too large for uint16)
func ReadUint16Bytes(b []byte) (uint16, []byte, error) {
	v, o, err := ReadUint64Bytes(b)
	if v > math.MaxUint16 {
		return 0, nil, UintOverflow{Value: v, FailedBitsize: 16}
	}
	return uint16(v), o, err
}

// ReadUint8Bytes tries to read a uint8
// from 'b' and return the value and the remaining bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a uint)
// - UintOverflow{} (value too large for uint8)
func ReadUint8Bytes(b []byte) (uint8, []byte, error) {
	v, o, err := ReadUint64Bytes(b)
	if v > math.MaxUint8 {
		return 0, nil, UintOverflow{Value: v, FailedBitsize: 8}
	}
	return uint8(v), o, err
}

// ReadByteBytes is analogous to ReadUint8Bytes
func ReadByteBytes(b []byte) (byte, []byte, error) {
	return ReadUint8Bytes(b)
}

// ReadBytesBytes reads a 'bin' object
// from 'b' and returns its value and
// the remaining bytes in 'b'.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a 'bin' object)
func ReadBytesBytes(b []byte, scratch []byte) (v []byte, o []byte, err error) {
	return readBytesBytes(b, scratch, false, true)
}

func readBytesBytesSlow(b []byte, flattenMap bool) (v []byte, o []byte, err error) {
	var count int
	count, _, o, err = readArrayHeaderBytes(b, flattenMap)
	if err != nil {
		return
	}

	if len(o) < count {
		err = ErrShortBytes
		return
	}

	v = make([]byte, count)
	for idx := range v {
		v[idx], o, err = ReadByteBytes(o)
		if err != nil {
			return
		}
	}

	return
}

// ReadBytesBytesHeader reads the header of a 'bin' object
// from 'b' and return it's length, in bytes.
// Possible errors:
// - ErrShortBytes (too few bytes)
// - TypeError{} (not a 'bin' object)
func ReadBytesBytesHeader(b []byte) (sz int, err error) {
	l := len(b)
	if l < 1 {
		return 0, ErrShortBytes
	}

	lead := b[0]

	// go-codec compat: decode string encodings into byte arrays

	if isfixstr(lead) {
		sz = int(rfixstr(lead))
		return
	}

	switch lead {
	case mstr8:
		if l < 2 {
			err = ErrShortBytes
			return
		}
		sz = int(b[1])
		return

	case mstr16:
		if l < 3 {
			err = ErrShortBytes
			return
		}
		sz = int(big.Uint16(b[1:]))
		return

	case mstr32:
		if l < 5 {
			err = ErrShortBytes
			return
		}
		sz, err = u32int(big.Uint32(b[1:]))
		return

	case mnil:
		sz = 0
		return

	case mbin8:
		if l < 2 {
			err = ErrShortBytes
			return
		}
		sz = int(b[1])
		return

	case mbin16:
		if l < 3 {
			err = ErrShortBytes
			return
		}
		sz = int(big.Uint16(b[1:]))
		return

	case mbin32:
		if l < 5 {
			err = ErrShortBytes
			return
		}
		sz, err = u32int(big.Uint32(b[1:]))
		return

	default:
		sz, _, _, err = readArrayHeaderBytes(b, true)
		return
	}
}

func readBytesBytes(b []byte, scratch []byte, zc bool, flattenMap bool) (v []byte, o []byte, err error) {
	l := len(b)
	if l < 1 {
		return nil, nil, ErrShortBytes
	}

	lead := b[0]
	var read int

	// go-codec compat: decode string encodings into byte arrays

	if isfixstr(lead) {
		read = int(rfixstr(lead))
		b = b[1:]
	} else {
		switch lead {
		case mstr8:
			if l < 2 {
				err = ErrShortBytes
				return
			}
			read = int(b[1])
			b = b[2:]

		case mstr16:
			if l < 3 {
				err = ErrShortBytes
				return
			}
			read = int(big.Uint16(b[1:]))
			b = b[3:]

		case mstr32:
			if l < 5 {
				err = ErrShortBytes
				return
			}
			read, err = u32int(big.Uint32(b[1:]))
			if err != nil {
				return
			}
			b = b[5:]

		case mnil:
			v = nil
			o = b[1:]
			return

		case mbin8:
			if l < 2 {
				err = ErrShortBytes
				return
			}
			read = int(b[1])
			b = b[2:]

		case mbin16:
			if l < 3 {
				err = ErrShortBytes
				return
			}
			read = int(big.Uint16(b[1:]))
			b = b[3:]

		case mbin32:
			if l < 5 {
				err = ErrShortBytes
				return
			}
			read, err = u32int(big.Uint32(b[1:]))
			if err != nil {
				return
			}
			b = b[5:]

		default:
			// go-codec compat: decode into byte array/slice from
			// explicit array encodings (including the weird case
			// of decoding a map as a key-value interleaved array).
			v, o, err = readBytesBytesSlow(b, flattenMap)
			if err != nil {
				// If that doesn't work, return the original error code.
				err = badPrefix(BinType, lead)
			}
			return
		}
	}

	if len(b) < read {
		err = ErrShortBytes
		return
	}

	// zero-copy
	if zc {
		v = b[0:read]
		o = b[read:]
		return
	}

	// The "scratch != nil" check is to match go-codec behavior:
	// decode zero-length byte slices as a non-nil byte slice.
	if scratch != nil && cap(scratch) >= read {
		v = scratch[0:read]
	} else {
		v = make([]byte, read)
	}

	o = b[copy(v, b):]
	return
}

// ReadBytesZC extracts the messagepack-encoded
// binary field without copying. The returned []byte
// points to the same memory as the input slice.
// Possible errors:
// - ErrShortBytes (b not long enough)
// - TypeError{} (object not 'bin')
func ReadBytesZC(b []byte) (v []byte, o []byte, err error) {
	return readBytesBytes(b, nil, true, true)
}

func readExactBytesSlow(b []byte, into []byte) (o []byte, err error) {
	var count int
	count, _, o, err = ReadArrayHeaderBytes(b)
	if err != nil {
		return
	}

	if count > len(into) {
		err = ArrayError{Wanted: len(into), Got: count}
		return
	}

	for idx := 0; idx < count; idx++ {
		into[idx], o, err = ReadByteBytes(o)
		if err != nil {
			return
		}
	}

	return
}

func ReadExactBytes(b []byte, into []byte) (o []byte, err error) {
	l := len(b)
	if l < 1 {
		err = ErrShortBytes
		return
	}

	lead := b[0]
	var read int
	var skip int

	// go-codec compat: decode string encodings into byte arrays

	if isfixstr(lead) {
		read = int(rfixstr(lead))
		skip = 1
	} else {
		switch lead {
		case mstr8:
			if l < 2 {
				err = ErrShortBytes
				return
			}
			read = int(b[1])
			skip = 2

		case mstr16:
			if l < 3 {
				err = ErrShortBytes
				return
			}
			read = int(big.Uint16(b[1:]))
			skip = 3

		case mstr32:
			if l < 5 {
				err = ErrShortBytes
				return
			}
			read, err = u32int(big.Uint32(b[1:]))
			if err != nil {
				return
			}
			skip = 5

		case mnil:
			// go-codec compat: decoding nil into an array clears the array;
			// different from decoding a zero-length array (which updates
			// in-place).
			for i := range into {
				into[i] = 0
			}
			read = 0
			skip = 1

		case mbin8:
			if l < 2 {
				err = ErrShortBytes
				return
			}
			read = int(b[1])
			skip = 2

		case mbin16:
			if l < 3 {
				err = ErrShortBytes
				return
			}
			read = int(big.Uint16(b[1:]))
			skip = 3

		case mbin32:
			if l < 5 {
				err = ErrShortBytes
				return
			}
			read, err = u32int(big.Uint32(b[1:]))
			if err != nil {
				return
			}
			skip = 5

		default:
			// go-codec compat: decode into byte array from
			// explicit array encodings (including the weird case
			// of decoding a map as a key-value interleaved array).
			o, err = readExactBytesSlow(b, into)
			if err != nil {
				// If that doesn't work, return the original error code.
				err = badPrefix(BinType, lead)
			}
			return
		}
	}

	// go-codec compat: allow decoding a different number of bytes than the
	// size of the fixed array; take the min of the size of the Go type and
	// the encoded array size.
	//
	// if read != len(into) {
	// 	err = ArrayError{Wanted: uint32(len(into)), Got: uint32(read)}
	// 	return
	// }

	if read > len(b[skip:]) {
		err = ErrShortBytes
		return
	}

	copy(into, b[skip:skip+read])
	o = b[skip+read:]
	return
}

// ReadStringZC reads a messagepack string field
// without copying. The returned []byte points
// to the same memory as the input slice.
// Possible errors:
// - ErrShortBytes (b not long enough)
// - TypeError{} (object not 'str')
func ReadStringZC(b []byte) (v []byte, o []byte, err error) {
	l := len(b)
	if l < 1 {
		return nil, nil, ErrShortBytes
	}

	lead := b[0]
	var read int

	if isfixstr(lead) {
		read = int(rfixstr(lead))
		b = b[1:]
	} else {
		switch lead {
		case mnil:
			read = 0
			b = b[1:]

		case mstr8:
			if l < 2 {
				err = ErrShortBytes
				return
			}
			read = int(b[1])
			b = b[2:]

		case mstr16:
			if l < 3 {
				err = ErrShortBytes
				return
			}
			read = int(big.Uint16(b[1:]))
			b = b[3:]

		case mstr32:
			if l < 5 {
				err = ErrShortBytes
				return
			}
			read, err = u32int(big.Uint32(b[1:]))
			if err != nil {
				return
			}
			b = b[5:]

		default:
			// go-codec compat: decode bin types into string
			v, o, err = readBytesBytes(b, nil, true, false)
			if err != nil {
				// If the fallback fails, return original error code
				err = TypeError{Method: StrType, Encoded: getType(lead)}
			}
			return
		}
	}

	if len(b) < read {
		err = ErrShortBytes
		return
	}

	v = b[0:read]
	o = b[read:]
	return
}

// ReadStringBytes reads a 'str' object
// from 'b' and returns its value and the
// remaining bytes in 'b'.
// Possible errors:
// - ErrShortBytes (b not long enough)
// - TypeError{} (not 'str' type)
// - InvalidPrefixError
func ReadStringBytes(b []byte) (string, []byte, error) {
	v, o, err := ReadStringZC(b)
	return string(v), o, err
}

// ReadStringAsBytes reads a 'str' object
// into a slice of bytes. 'v' is the value of
// the 'str' object, which may reside in memory
// pointed to by 'scratch.' 'o' is the remaining bytes
// in 'b'.
// Possible errors:
// - ErrShortBytes (b not long enough)
// - TypeError{} (not 'str' type)
// - InvalidPrefixError (unknown type marker)
func ReadStringAsBytes(b []byte, scratch []byte) (v []byte, o []byte, err error) {
	var tmp []byte
	tmp, o, err = ReadStringZC(b)
	v = append(scratch[:0], tmp...)
	return
}

// ReadComplex128Bytes reads a complex128
// extension object from 'b' and returns the
// remaining bytes.
// Possible errors:
// - ErrShortBytes (not enough bytes in 'b')
// - TypeError{} (object not a complex128)
// - InvalidPrefixError
// - ExtensionTypeError{} (object an extension of the correct size, but not a complex128)
func ReadComplex128Bytes(b []byte) (c complex128, o []byte, err error) {
	if len(b) < 18 {
		err = ErrShortBytes
		return
	}
	if b[0] != mfixext16 {
		err = badPrefix(Complex128Type, b[0])
		return
	}
	if int8(b[1]) != Complex128Extension {
		err = errExt(int8(b[1]), Complex128Extension)
		return
	}
	c = complex(math.Float64frombits(big.Uint64(b[2:])),
		math.Float64frombits(big.Uint64(b[10:])))
	o = b[18:]
	return
}

// ReadComplex64Bytes reads a complex64
// extension object from 'b' and returns the
// remaining bytes.
// Possible errors:
// - ErrShortBytes (not enough bytes in 'b')
// - TypeError{} (object not a complex64)
// - ExtensionTypeError{} (object an extension of the correct size, but not a complex64)
func ReadComplex64Bytes(b []byte) (c complex64, o []byte, err error) {
	if len(b) < 10 {
		err = ErrShortBytes
		return
	}
	if b[0] != mfixext8 {
		err = badPrefix(Complex64Type, b[0])
		return
	}
	if b[1] != Complex64Extension {
		err = errExt(int8(b[1]), Complex64Extension)
		return
	}
	c = complex(math.Float32frombits(big.Uint32(b[2:])),
		math.Float32frombits(big.Uint32(b[6:])))
	o = b[10:]
	return
}

// ReadTimeBytes reads a time.Time
// extension object from 'b' and returns the
// remaining bytes.
// Possible errors:
// - ErrShortBytes (not enough bytes in 'b')
// - TypeError{} (object not a complex64)
// - ExtensionTypeError{} (object an extension of the correct size, but not a time.Time)
func ReadTimeBytes(b []byte) (t time.Time, o []byte, err error) {
	if len(b) < 1 {
		err = ErrShortBytes
		return
	}
	if b[0] == mnil {
		o = b[1:]
		return
	}
	if len(b) < 15 {
		err = ErrShortBytes
		return
	}
	if b[0] != mext8 || b[1] != 12 {
		err = badPrefix(TimeType, b[0])
		return
	}
	if int8(b[2]) != TimeExtension {
		err = errExt(int8(b[2]), TimeExtension)
		return
	}
	sec, nsec := getUnix(b[3:])
	t = time.Unix(sec, int64(nsec)).Local()
	o = b[15:]
	return
}

// Skip skips the next object in 'b' and
// returns the remaining bytes. If the object
// is a map or array, all of its elements
// will be skipped.
// Possible Errors:
// - ErrShortBytes (not enough bytes in b)
// - InvalidPrefixError (bad encoding)
func Skip(b []byte) ([]byte, error) {
	sz, asz, err := getSize(b)
	if err != nil {
		return b, err
	}
	if uintptr(len(b)) < sz {
		return b, ErrShortBytes
	}
	b = b[sz:]
	for asz > 0 {
		b, err = Skip(b)
		if err != nil {
			return b, err
		}
		asz--
	}
	return b, nil
}

// returns (skip N bytes, skip M objects, error)
func getSize(b []byte) (uintptr, uintptr, error) {
	l := len(b)
	if l == 0 {
		return 0, 0, ErrShortBytes
	}
	lead := b[0]
	spec := &sizes[lead] // get type information
	size, mode := spec.size, spec.extra
	if size == 0 {
		return 0, 0, InvalidPrefixError(lead)
	}
	if mode >= 0 { // fixed composites
		return uintptr(size), uintptr(mode), nil
	}
	if l < int(size) {
		return 0, 0, ErrShortBytes
	}
	switch mode {
	case extra8:
		return uintptr(size) + uintptr(b[1]), 0, nil
	case extra16:
		return uintptr(size) + uintptr(big.Uint16(b[1:])), 0, nil
	case extra32:
		return uintptr(size) + uintptr(big.Uint32(b[1:])), 0, nil
	case map16v:
		return uintptr(size), 2 * uintptr(big.Uint16(b[1:])), nil
	case map32v:
		return uintptr(size), 2 * uintptr(big.Uint32(b[1:])), nil
	case array16v:
		return uintptr(size), uintptr(big.Uint16(b[1:])), nil
	case array32v:
		return uintptr(size), uintptr(big.Uint32(b[1:])), nil
	default:
		return 0, 0, fatal
	}
}
