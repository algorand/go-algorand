// Copyright (C) 2019-2020 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package memory

import (
	"errors"
	"fmt"
	"github.com/algorand/go-algorand/data/basics/newpkg/binary"
	"io"
	"log"
)

const (
	MaxSegmentSize        = 128 * 1024 * 1024
	DefaultMinPackingGain = 0.15
	DefaultPointerCost    = 8
)

const NilTypeID = 0

type DataType interface {
	binary.MarshalerTo
	String() string
	// Cost returns the cost that protocol defines for every teal.DataType. This cost should not be dependant to
	// the specific implementation used.
	Cost() int
	TypeID() uint8
}

type DataTypeReader func(reader io.ByteReader) (DataType, error)

// ===============================
// DataType readers:

var readers = make(map[uint8]DataTypeReader)

// RegisterReader
func RegisterReader(typeID uint8, r DataTypeReader) {
	if typeID == NilTypeID {
		log.Panicf("%d is reserved for nil datatype", typeID)
	}
	if _, exists := readers[typeID]; exists {
		log.Panicf("Already a reader is registered for typeID: %d", typeID)
	}
	readers[typeID] = r
}

// ===============================
// Cost calculation functions:

// CostAfterAdding
var CostAfterAdding = func(oldCost int, dt DataType) (newCost int) {
	return oldCost + dt.Cost()
}

// CostAfterRemoving
var CostAfterRemoving = func(oldCost int, dt DataType) (newCost int) {
	return oldCost - dt.Cost()
}

// EmptySegmentCost returns the protocol defined cost of an empty memory.Segment with the specified size.
var EmptySegmentCost = func(size int) int {
	return size * DefaultPointerCost
}

// ===============================
// Errors:

var (
	ErrCellNotEmpty    = errors.New("memory cell is not empty")
	ErrCellIsEmpty     = errors.New("memory cell is empty")
	ErrMaxCostExceeded = errors.New("max protocol's cost is exceeded")
	ErrValueTooBig     = errors.New("value is too big")
)

// OutOfBoundsError is an error type indicating that some integer value is out of its valid range.
type OutOfBoundsError struct {
	Value       int
	LowerBound  int
	HigherBound int
}

func (orErr *OutOfBoundsError) Error() string {
	return fmt.Sprintf("out of bounds: %d is not between %d and %d", orErr.Value, orErr.LowerBound, orErr.HigherBound)
}
