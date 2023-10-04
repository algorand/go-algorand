package msgp

// Sizer is an interface implemented
// by types that can estimate their
// size when MessagePack encoded.
// This interface is optional, but
// encoding/marshaling implementations
// may use this as a way to pre-allocate
// memory for serialization.
type Sizer interface {
	Msgsize() int
}

// MaxSizer is an interface implemented
// by types that can determine their max
// when implemented.
// This interface is optional, but
// implementations may use this as a way to limit
// number of bytes read during deserialization
type MaxSizer interface {
	MaxSize() int
}

// Require ensures that cap(old)-len(old) >= extra.
// It might be that this is impossible because len(old)+extra
// overflows int.  If so, Require will not grow the slice,
// but at this point, we have run out of memory, and panic
// (from subsequent out-of-bounds access) is as good of an
// outcome as any.
func Require(old []byte, extra int) []byte {
	l := len(old)
	c := cap(old)
	r := l + extra
	if c >= r {
		return old
	} else if l == 0 {
		return make([]byte, 0, extra)
	}
	// the new size is the greater
	// of double the old capacity
	// and the sum of the old length
	// and the number of new bytes
	// necessary.
	c <<= 1
	if c < r {
		c = r
	}
	n := make([]byte, l, c)
	copy(n, old)
	return n
}

// Marshaler is the interface implemented
// by types that know how to marshal themselves
// as MessagePack. MarshalMsg appends the marshalled
// form of the object to the provided
// byte slice, returning the extended slice.
// CanMarshalMsg checks that o is of the same type as
// was used to generate the MarshalMsg code; it can be
// used to guard against MarshalMsg() going to an embedded
// field in a struct rather than marshaling the entire struct.
type Marshaler interface {
	MarshalMsg([]byte) []byte
	CanMarshalMsg(o interface{}) bool
}
