package assembler

// OpSpec defines one byte opcode
type OpSpec struct {
	Opcode  byte
	Name    string
	Args    []StackType // what gets popped from the stack
	Returns []StackType // what gets pushed to the stack
}

var oneBytes = []StackType{StackBytes}
var threeBytes = []StackType{StackBytes, StackBytes, StackBytes}
var oneInt = []StackType{StackUint64}
var twoInts = []StackType{StackUint64, StackUint64}
var oneAny = []StackType{StackAny}
var twoAny = []StackType{StackAny, StackAny}

// OpSpecs is the table of operations that can be assembled and evaluated.
//
// Any changes should be reflected in README.md which serves as the language spec.
var OpSpecs = []OpSpec{
	{0x00, "err", nil, nil},
	{0x01, "sha256", oneBytes, oneBytes},
	{0x02, "keccak256", oneBytes, oneBytes},
	{0x03, "sha512_256", oneBytes, oneBytes},
	{0x04, "ed25519verify", threeBytes, oneInt},
	{0x08, "+", twoInts, oneInt},
	{0x09, "-", twoInts, oneInt},
	{0x0a, "/", twoInts, oneInt},
	{0x0b, "*", twoInts, oneInt},
	{0x0c, "<", twoInts, oneInt},
	{0x0d, ">", twoInts, oneInt},
	{0x0e, "<=", twoInts, oneInt},
	{0x0f, ">=", twoInts, oneInt},
	{0x10, "&&", twoInts, oneInt},
	{0x11, "||", twoInts, oneInt},
	{0x12, "==", twoAny, oneInt},
	{0x13, "!=", twoAny, oneInt},
	{0x14, "!", oneInt, oneInt},
	{0x15, "len", oneBytes, oneInt},
	{0x16, "itob", oneInt, oneBytes},
	{0x17, "btoi", oneBytes, oneInt},
	{0x18, "%", twoInts, oneInt},
	{0x19, "|", twoInts, oneInt},
	{0x1a, "&", twoInts, oneInt},
	{0x1b, "^", twoInts, oneInt},
	{0x1c, "~", oneInt, oneInt},
	{0x1d, "mulw", twoInts, twoInts},

	{0x20, "intcblock", nil, nil},
	{0x21, "intc", nil, oneInt},
	{0x22, "intc_0", nil, oneInt},
	{0x23, "intc_1", nil, oneInt},
	{0x24, "intc_2", nil, oneInt},
	{0x25, "intc_3", nil, oneInt},
	{0x26, "bytecblock", nil, nil},
	{0x27, "bytec", nil, oneBytes},
	{0x28, "bytec_0", nil, oneBytes},
	{0x29, "bytec_1", nil, oneBytes},
	{0x2a, "bytec_2", nil, oneBytes},
	{0x2b, "bytec_3", nil, oneBytes},
	{0x2c, "arg", nil, oneBytes},
	{0x2d, "arg_0", nil, oneBytes},
	{0x2e, "arg_1", nil, oneBytes},
	{0x2f, "arg_2", nil, oneBytes},
	{0x30, "arg_3", nil, oneBytes},
	{0x31, "txn", nil, oneAny},    // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x32, "global", nil, oneAny}, // TODO: check output type against specific field
	{0x33, "gtxn", nil, oneAny},   // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x34, "load", nil, oneAny},
	{0x35, "store", oneAny, nil},

	{0x40, "bnz", oneInt, nil},
	{0x48, "pop", oneAny, nil},
	{0x49, "dup", oneAny, twoAny},
}

// direct opcode bytes
var opsByOpcode []OpSpec
