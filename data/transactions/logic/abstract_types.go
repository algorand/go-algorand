package logic

import (
	"math"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
)

type AbstractType int

const (
	// AVM base types
	AbstractNone AbstractType = iota
	AbstractAny
	AbstractBytes
	AbstractUint64

	// TODO: Generate strings for these?
	// Higher level types that are common enough to be named
	AbstractBool
	AbstractHash
	AbstractAddress
	AbstractBigInt
)

func (at AbstractType) String() string {
	switch at {
	// AVM base types
	case AbstractNone:
		return "none"
	case AbstractAny:
		return "any"
	case AbstractBytes:
		return "bytes"
	case AbstractUint64:
		return "uint64"

	// TODO: Generate strings for these?
	// Higher level types that are common enough to be named
	case AbstractBool:
		return "boolean"
	case AbstractHash:
		return "hash"
	case AbstractAddress:
		return "address"
	case AbstractBigInt:
		return "bigint"
	default:
		panic(at)
	}
}

var (
	params = config.Consensus[protocol.ConsensusCurrentVersion]

	Uint64Bound = boundUint(0, math.MaxUint64).abstractType(AbstractUint64)
	BytesBound  = boundBytes(0, maxStringSize).abstractType(AbstractBytes)
	AnyBound    = TypeBound{
		StackType:    StackAny,
		AbstractType: AbstractAny,
		ValueRange:   Uint64Bound.ValueRange,
		LengthRange:  BytesBound.LengthRange,
	}
	NoneBound = TypeBound{
		StackType:    StackNone,
		AbstractType: AbstractNone,
		ValueRange:   []uint64{0, 0},
		LengthRange:  []uint64{0, 0},
	}

	// Some higher level types that are common
	BooleanBound = boundUint(0, 1).abstractType(AbstractBool)
	HashBound    = staticBytes(32).abstractType(AbstractHash)
	AddressBound = staticBytes(32).abstractType(AbstractAddress)
	BigIntBound  = boundBytes(0, maxByteMathSize).abstractType(AbstractBigInt) // TOOD: should min size be 1 be a 0?

	// These don't need to be here but makes them easier to see how it
	// might work while reviewing
	AppArgsNumBound = boundUint(0, uint64(params.MaxAppArgs))
	AppArgBound     = boundBytes(0, uint64(params.MaxAppTotalArgLen))

	AssetUrlBound      = boundBytes(0, uint64(params.MaxAssetURLBytes))
	AssetNameBound     = boundBytes(0, uint64(params.MaxAssetNameBytes))
	AssetUnitNameBound = boundBytes(0, uint64(params.MaxAssetUnitNameBytes))

	NoteFieldBound = boundBytes(0, uint64(params.MaxTxnNoteBytes))
	// ...

	TypeBounds = []TypeBound{
		NoneBound,
		AnyBound,
		Uint64Bound,
		BytesBound,
		BooleanBound,
		HashBound,
		AddressBound,
		BigIntBound,
	}
)

type TypeBound struct {
	StackType    StackType    // The lower level type it maps to
	AbstractType AbstractType // The higher level type
	ValueRange   []uint64     // If its an integer, what is the min/max values (inclusive)
	LengthRange  []uint64     // If its a bytestring, what is the min/max length (inclusive)
}

func (tb TypeBound) abstractType(at AbstractType) TypeBound {
	tb.AbstractType = at
	return tb
}

func boundUint(min, max uint64) TypeBound {
	return TypeBound{StackType: StackUint64, AbstractType: AbstractUint64, ValueRange: []uint64{min, max}}
}
func boundBytes(min, max uint64) TypeBound {
	return TypeBound{StackType: StackBytes, AbstractType: AbstractBytes, LengthRange: []uint64{min, max}}
}
func staticBytes(size uint64) TypeBound {
	return boundBytes(size, size)
}
