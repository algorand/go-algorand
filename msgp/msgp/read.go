package msgp

// Type is a MessagePack wire type,
// including this package's built-in
// extension types.
type Type byte

// MessagePack Types
//
// The zero value of Type
// is InvalidType.
const (
	InvalidType Type = iota

	// MessagePack built-in types

	StrType
	BinType
	MapType
	ArrayType
	Float64Type
	Float32Type
	BoolType
	IntType
	UintType
	NilType
	ExtensionType

	// pseudo-types provided
	// by extensions

	Complex64Type
	Complex128Type
	TimeType

	_maxtype
)

// String implements fmt.Stringer
func (t Type) String() string {
	switch t {
	case StrType:
		return "str"
	case BinType:
		return "bin"
	case MapType:
		return "map"
	case ArrayType:
		return "array"
	case Float64Type:
		return "float64"
	case Float32Type:
		return "float32"
	case BoolType:
		return "bool"
	case UintType:
		return "uint"
	case IntType:
		return "int"
	case ExtensionType:
		return "ext"
	case NilType:
		return "nil"
	default:
		return "<invalid>"
	}
}

// Unmarshaler is the interface fulfilled
// by objects that know how to unmarshal
// themselves from MessagePack.
// UnmarshalMsg unmarshals the object
// from binary, returing any leftover
// bytes and any errors encountered.
// CanUnmarshalMsg checks that o is of the same type as
// was used to generate the UnmarshalMsg code; it can be
// used to guard against UnmarshalMsg() going to an embedded
// field in a struct rather than unmarshaling the entire struct.
type Unmarshaler interface {
	UnmarshalMsg([]byte) ([]byte, error)
	UnmarshalMsgWithState([]byte, UnmarshalState) ([]byte, error)
	CanUnmarshalMsg(o interface{}) bool
}

// UnmarshalState holds state while running UnmarshalMsg.
type UnmarshalState struct {
	Depth uint64
}

// DefaultUnmarshalState defines the default state.
var DefaultUnmarshalState = UnmarshalState{Depth: 10000}
