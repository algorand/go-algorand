// Copyright (C) 2019-2021 Algorand, Inc.
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
	"fmt"
	"github.com/algorand/go-algorand/data/basics/newpkg/binary"
	"io"
	"log"
)

// Segment represents a fixed size segment of a random access memory which its starting address is 0.
// Every address can either be empty or contain a DataType.
//
// Segment is able to  save a snapshot of its state which can later be restored by calling RestoreSnapshot.
// After calling SaveSnapshot runtime overhead and memory usage of Segment increases, calling DiscardSnapshot will
// remove this overhead.
//
// By using MarshalBinaryTo a Segment can be efficiently serialized to a compact and simple binary representation.
// by using ReadSegment the Segment can be reconstructed from this binary representation.
//
// Any type which implements DataType interface can be stored in a Segment. To enable serialization, a newly defined type
// needs to register a DataTypeReader using RegisterReader function. Also for correct restoration of snapshots,
// the new DataType must use NotifyUpdate or NotifyUpdateWithKey method properly. Current implementation of memory
// package can support up to 126 different data types.
//
// The overall cost of a Segment can never be exceeded beyond MaxCost value. The value of MaxCost is set
// when creating a Segment and can be updated using SetMaxCost function. The cost calculation is done using
// Cost method in DataType interface and EmptySegmentCost, CostAfterAdding and CostAfterRemoving functions.
// These functions can be changed without recompiling the memory package.
//
// For a usage example see NewSegment.
type Segment struct {
	segment     []DataType
	snapManager snapshotManager
	maxSize     int
	cost        int
	maxCost     int
}

// NewSegment creates an empty Segment which its last valid address is 'size - 1' and its protocol defined
// cost will never exceed maxCost.
func NewSegment(size int, maxCost int) *Segment {
	if size > MaxSegmentSize {
		log.Panicf("%d is bigger than max allowed segment size: %d", size, MaxSegmentSize)
	}
	r := &Segment{
		segment: make([]DataType, size),
		maxSize: size,
		// the cost of an empty memory segment:
		cost: EmptySegmentCost(size),
	}
	r.SetMaxCost(maxCost)
	return r
}

// ReadSegment reads the binary representation of a Segment from an io.ByteReader.
func ReadSegment(r io.ByteReader) (*Segment, error) {
	temp, err := binary.ReadUInt(r)
	if err != nil {
		return nil, binary.NewSimpleDecodingErr("size", err)
	}
	size := int(temp)
	if size < 0 || size > MaxSegmentSize {
		return nil, binary.NewSimpleDecodingErr("size", ErrValueTooBig)
	}
	temp, err = binary.ReadUInt(r)
	if err != nil {
		return nil, binary.NewSimpleDecodingErr("maxCost", err)
	}
	maxCost := int(temp)
	ms := &Segment{
		segment: make([]DataType, size),
		maxSize: size,
		maxCost: maxCost,
	}
	var typeID uint8
	var count int
	for start := 0; start < len(ms.segment); {
		typeID, err = r.ReadByte()
		if err != nil {
			return nil, binary.NewSimpleDecodingErr(fmt.Sprintf("segment[%d].typeID", start), err)
		}
		if typeID > 0x7F {
			typeID &= 0x7F
			count = 1
		} else {
			temp, err = binary.ReadUInt(r)
			if err != nil {
				return nil, binary.NewSimpleDecodingErr(fmt.Sprintf("segment[%d](T:%d).count", start, typeID), err)
			}
			count = int(temp)
		}
		if count < 0 || start+count > len(ms.segment) {
			return nil, binary.NewSimpleDecodingErr(fmt.Sprintf("segment[%d](T:%d).count", start, typeID), ErrValueTooBig)
		}
		if typeID != NilTypeID {
			dtReader := readers[typeID]
			for i := start; i < start+count; i++ {
				ms.segment[i], err = dtReader(r)
				if err != nil {
					return nil, binary.NewSimpleDecodingErr(fmt.Sprintf("segment[%d]", i), err)
				}
			}
		}
		start += count
	}
	ms.cost = ms.calculateCost()
	if ms.cost > ms.maxCost {
		return nil, binary.NewSimpleDecodingErr("maxCost", ErrMaxCostExceeded)
	}
	return ms, nil
}

// AllocateAt puts 'item' at the specified position by 'index'. If that position is not empty it will return
// ErrCellNotEmpty.
//
// If after adding item the cost of Segment exceeds the maxCost the item will
// not be added and ErrMaxCostExceeded will be returned.
func (ms *Segment) AllocateAt(index int, item DataType) error {
	if item == nil {
		log.Panic("input item can't be nil.")
	}
	if index < 0 || index >= ms.maxSize {
		return &OutOfBoundsError{Value: index, LowerBound: 0, HigherBound: ms.maxSize - 1}
	}
	if ms.segment[index] != nil {
		return ErrCellNotEmpty
	}
	if CostAfterAdding(ms.cost, item) > ms.maxCost {
		return ErrMaxCostExceeded
	}
	// we need to notify our snapshot manager about change in segment[]
	ms.snapManager.notifyUpdate(&ms.segment[index], ms.segment[index])
	// adding item
	ms.segment[index] = item
	// we save a snapshot of the old cost
	ms.snapManager.notifyUpdate(&ms.cost, ms.cost)
	ms.cost = CostAfterAdding(ms.cost, item)
	return nil
}

// Delete deletes any data stored at the specified position by 'index'. it returns an error if that memory location is empty.
func (ms *Segment) Delete(index int) error {
	// if Get(index) returns an error we will return an error too
	if _, err := ms.Get(index); err != nil {
		return err
	}

	ms.snapManager.notifyUpdate(&ms.cost, ms.cost)
	ms.cost = CostAfterRemoving(ms.cost, ms.segment[index])
	// we need to notify our snapshot manager about change in segment[]
	ms.snapManager.notifyUpdate(&ms.segment[index], ms.segment[index])
	// removing item
	ms.segment[index] = nil
	return nil
}

// Get retrieves the data stored at the memory position specified by 'index'. it returns an error if that memory
// location is empty
func (ms *Segment) Get(index int) (DataType, error) {
	if index < 0 || index >= ms.maxSize {
		return nil, &OutOfBoundsError{Value: index, LowerBound: 0, HigherBound: ms.maxSize - 1}
	}
	if index >= len(ms.segment) || ms.segment[index] == nil {
		return nil, ErrCellIsEmpty
	}
	return ms.segment[index], nil
}

// SaveSnapshot saves a snapshot of the current state of Segment. After calling SaveSnapshot the memory
// usage of Segment increases and updating any data will have an extra overhead.
func (ms *Segment) SaveSnapshot() {
	ms.snapManager.reset()
}

// DiscardSnapshot discards any snapshots saved in Segment. This will improve memory usage of Segment.
func (ms *Segment) DiscardSnapshot() {
	ms.snapManager.turnOff()
}

// RestoreSnapshot restores a previously saved snapshot.
func (ms *Segment) RestoreSnapshot() {
	ms.snapManager.restoreSnapshot()
	// we don't need the old snapshot anymore, so we reset snapManager to improve performance of memory segment
	ms.snapManager.reset()
}

// MarshalBinaryTo will write the binary representation of this memory segment using an io.Writer. The format of
// this representation is as follows: ...
func (ms *Segment) MarshalBinaryTo(w io.Writer) (n int, err error) {
	sw := binary.NewSilentWriter(w)
	sw.WriteUInt(uint64(ms.maxSize))
	sw.WriteUInt(uint64(ms.maxCost))
	recursiveWrite(ms.segment, sw)
	return sw.Count(), sw.Error()
}

// NotifyUpdate notifies this memory Segment that a value which is stored inside this memory Segment has changed. 'pointer' is a
// pointer to that value which essentially must be a go's primitive data type. This pointer will be used for rewriting
// the saved snapshot of that value when RestoreSnapshot is called. NotifyUpdate can only
// be used for data types that have a fixed location in RAM. DataTypes without a fixed memory location, like maps or
// dynamic lists, should only use NotifyUpdateWithKey method.
func (ms *Segment) NotifyUpdate(pointer interface{}, oldValue interface{}) {
	ms.snapManager.notifyUpdate(pointer, oldValue)
}

// NotifyUpdateWithKey notifies this memory Segment that a value which is stored inside this memory Segment has changed.
// This value belongs to a DataType that implements the Restorer interface and is the 'owner' of this value.
// 'internalKey' is any type of internal address Restorer uses for relocating the internal value that its state must be restored.
// 'OldValue' represents the old state of Restorer that must be restored after calling RestoreSnapshot.
// Only the oldest 'oldValue' for any (owner, internalKey) pair will be kept.
func (ms *Segment) NotifyUpdateWithKey(owner Restorer, internalKey string, oldValue interface{}) {
	ms.snapManager.notifyUpdateWithKey(owner, internalKey, oldValue)
}

// MaxCost returns the maximum protocol defined cost that this Segment may have. The overall cost of a Segment can
// never be exceeded beyond MaxCost value.
func (ms *Segment) MaxCost() int {
	return ms.maxCost
}

// SetMaxCost sets a new maximum cost for the Segment and panics if the new maxCost is not a valid cost.
func (ms *Segment) SetMaxCost(maxCost int) {
	if ms.cost > maxCost {
		log.Panicf("maxCost's already exceeded. current cost is %d.", ms.cost)
	}
	ms.maxCost = maxCost
}

// CurrentCost returns the current cost of Segment as defined in the protocol.
func (ms *Segment) CurrentCost() int {
	return ms.cost
}

func (ms *Segment) String() string {
	str := fmt.Sprintf("Memory Segment: (maxSize:%d) (maxCost:%d)", ms.maxSize, ms.maxCost)
	for i, data := range ms.segment {
		str += fmt.Sprintf("\n[%d, %T)]--->%v", i, data, data)
	}
	str += fmt.Sprintf("\nCost:%d/%d", ms.cost, ms.maxCost)
	str += fmt.Sprintf("\nSaved Snapshots:%v", &ms.snapManager)
	return str
}

// Content returns a text representation of this Segment which is less verbose than String() and only shows
// the main content of Segment.
func (ms *Segment) Content() string {
	str := fmt.Sprintf("Memory Segment: (maxSize:%d)", ms.maxSize)
	for i, data := range ms.segment {
		str += fmt.Sprintf("\n[%d, %T)]--->%v", i, data, data)
	}
	return str
}

func recursiveWrite(data []DataType, sw *binary.SilentWriter) {
	if len(data) == 0 {
		return
	}
	var count int
	for count = 0; count < len(data) && sameType(data[count], data[0]); count++ {
	}
	var typeID uint8
	if data[0] == nil {
		typeID = NilTypeID
	} else {
		typeID = data[0].TypeID()
	}
	if typeID > 0x7F {
		log.Panicf("typeID %d is bigger than 127", typeID)
	}
	if count == 1 {
		sw.SilentWriteBytes([]byte{typeID | 0x80})
	} else {
		sw.SilentWriteBytes([]byte{typeID})
		sw.WriteUInt(uint64(count))
	}
	if data[0] != nil {
		for i := 0; i < count; i++ {
			sw.SilentWriteMarshaler(data[i])
		}
	}
	recursiveWrite(data[count:], sw)
}

func sameType(a DataType, b DataType) bool {
	if a != nil && b != nil {
		return a.TypeID() == b.TypeID()
	} else {
		return a == nil && b == nil
	}
}

func (ms *Segment) calculateCost() (cost int) {
	cost = EmptySegmentCost(ms.maxSize)
	for _, dataType := range ms.segment {
		if dataType != nil {
			cost = CostAfterAdding(cost, dataType)
		}
	}
	return
}
