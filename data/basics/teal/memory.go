package teal

import (
	"errors"
	"fmt"
)

var (
	ErrCellNotEmpty = errors.New("memory cell is not empty")
	ErrCellIsEmpty  = errors.New("memory cell is empty")
)

// MemorySegment represents a fixed size segment of a random access memory which its starting address is 0.
// Every address can either be empty or contain a teal.DataType.
//
// MemorySegment is able to  save a snapshot of its state which can later be restored by calling RestoreSnapshot.
// After calling SaveSnapshot memory and runtime overhead of MemorySegment increases, calling DiscardSnapshot will re-optimize MemorySegment.
//
// Example Usage:
//		m := teal.NewMemorySegment(schemaSize)
//		m.SaveSnapshot()
//		err := runContract()
//		if err != nil {
//			m.RestoreSnapshot()
//		}
//		m.DiscardSnapshot()
type MemorySegment struct {
	segment     []DataType
	snapManager snapshotManager
	maxSize     int
	// MinPackingGain determines when DiscardSnapshot should not compact the segment. If the improvement in the size
	// of the segment is less than MinPackingGain the segment will not be copied to a smaller segment.
	MinPackingGain float32
}

// NewMemorySegment creates an empty MemorySegment which its last valid address is size - 1.
func NewMemorySegment(size int) *MemorySegment {
	return &MemorySegment{
		segment:        make([]DataType, size),
		maxSize:        size,
		MinPackingGain: 0.15,
	}
}

// AllocateAt puts "item" at the specified position by "index". If that position is not empty it will return an error.
// If the MemorySegment is compacted and the index is outside of the compacted memory, AllocateAt will
// try to expand the MemorySegment.
func (ms *MemorySegment) AllocateAt(index int, item DataType) error {
	if item == nil {
		panic("input item can't be nil.")
	}
	if index < 0 || index >= ms.maxSize {
		return &OutOfBoundsError{Value: index, LowerBound: 0, HigherBound: ms.maxSize - 1}
	}
	if index >= len(ms.segment) {
		ms.expand()
	}
	if ms.segment[index] != nil {
		return ErrCellNotEmpty
	}
	// we need to notify our snapshot manager about change in segment[]
	ms.snapManager.notifyUpdate(&ms.segment[index], ms.segment[index])
	// adding item
	ms.segment[index] = item
	return nil
}

// Delete deletes any data stored at the specified position by index. it returns an error if that memory location is empty.
func (ms *MemorySegment) Delete(index int) error {
	// if Get(index) returns an error we will return an error too
	if _, err := ms.Get(index); err != nil {
		return err
	}
	// we need to notify our snapshot manager about change in segment[]
	ms.snapManager.notifyUpdate(&ms.segment[index], ms.segment[index])
	// removing item
	ms.segment[index] = nil
	return nil
}

// Get retrieves the data stored at the memory position specified by index. it returns an error if that memory
// location is empty
func (ms *MemorySegment) Get(index int) (DataType, error) {
	if index < 0 || index >= ms.maxSize {
		return nil, &OutOfBoundsError{Value: index, LowerBound: 0, HigherBound: ms.maxSize - 1}
	}
	if index >= len(ms.segment) || ms.segment[index] == nil {
		return nil, ErrCellIsEmpty
	}
	return ms.segment[index], nil
}

// SaveSnapshot saves a snapshot of the current state of MemorySegment. If the MemorySegment is compacted it will
// expand it to its original size. After calling SaveSnapshot the memory usage of MemorySegment increases
// and updating any data will have an extra overhead.
func (ms *MemorySegment) SaveSnapshot() {
	ms.snapManager.reset()
	// we'd better call expand() here. otherwise AllocateAt may fail if the memory is updated.
	ms.expand()
}

// DiscardSnapshot discards any snapshots saved in MemorySegment. It also compacts MemorySegment to optimize its memory
// usage.
func (ms *MemorySegment) DiscardSnapshot() {
	ms.snapManager.turnOff()
	ms.compact()
}

// RestoreSnapshot restores a previously saved snapshot.
func (ms *MemorySegment) RestoreSnapshot() {
	ms.snapManager.restoreSnapshot()
	// we don't need the old snapshot anymore, so we reset snapManager to improve performance of MemorySegment
	ms.snapManager.reset()
}

// expand expands the memory to its original size. Expanding will cause a runtime error, if there is
// a non empty saved snapshot in the MemorySegment.
func (ms *MemorySegment) expand() {
	if len(ms.segment) == ms.maxSize {
		return
	}
	if len(ms.snapManager.savedSnapshots) > 0 {
		panic("We can not expand while there is a saved snapshot!")
	}
	newSegment := make([]DataType, ms.maxSize)
	copy(newSegment, ms.segment)
	ms.segment = newSegment
}

func (ms *MemorySegment) compact() {
	// when we have a saved snapshot compact does nothing
	if len(ms.snapManager.savedSnapshots) > 0 {
		return
	}
	// we need to find last element like this cuz we have a Delete() function which can remove elements
	oldLen := len(ms.segment)
	last := oldLen - 1
	for ; last >= 0 && ms.segment[last] == nil; last-- {
	}
	newLen := last + 1
	if float32(newLen) >= (1-ms.MinPackingGain)*float32(oldLen) {
		return
	}
	newSegment := make([]DataType, newLen)
	copy(newSegment, ms.segment)
	ms.segment = newSegment
}

func (ms *MemorySegment) Dump() string {
	str := fmt.Sprintf("Memory Segment: (maxSize:%d)", ms.maxSize)
	for i, data := range ms.segment {
		str += fmt.Sprintf("\n[%d, %T)]--->%v", i, data, data)
	}
	str += fmt.Sprintf("\nSaved Snapshots:%v", &ms.snapManager)
	return str
}

func (ms *MemorySegment) String() string {
	str := fmt.Sprintf("Memory Segment: (maxSize:%d)", ms.maxSize)
	for i, data := range ms.segment {
		str += fmt.Sprintf("\n[%d, %T)]--->%v", i, data, data)
	}
	return str
}

type snapshotManager struct {
	savedSnapshots map[interface{}]interface{}
}

func (sm *snapshotManager) reset() {
	sm.savedSnapshots = make(map[interface{}]interface{})
}

func (sm *snapshotManager) turnOff() {
	sm.savedSnapshots = nil
}

func (sm *snapshotManager) restoreSnapshot() {
	if sm.savedSnapshots == nil {
		panic("For restoring a snapshot u need to save one first!")
	}
	for pointer, value := range sm.savedSnapshots {
		switch p := pointer.(type) {
		case *DataType:
			if value == nil {
				*p = nil
			} else {
				*p = value.(DataType)
			}
		case *uint64:
			*p = value.(uint64)
		case *int64:
			*p = value.(int64)
		case *byte:
			*p = value.(byte)
		case *bool:
			*p = value.(bool)
		case *float64:
			*p = value.(float64)
		default:
			panic("It seems that you are trying to add a new teal.DataType but you forgot to change this function!")
		}
	}
}

func (sm *snapshotManager) notifyUpdate(pointer interface{}, oldValue interface{}) {
	// if sm.savedSnapshots is nil that means the snapshotManager is turned off and this function has no effect.
	if sm.savedSnapshots == nil {
		return
	}
	if _, exists := sm.savedSnapshots[pointer]; !exists {
		sm.savedSnapshots[pointer] = oldValue
	}
}

func (sm *snapshotManager) String() string {
	if sm.savedSnapshots == nil {
		return "<nil>"
	}
	str := "["
	for _, v := range sm.savedSnapshots {
		str += fmt.Sprintf("(%T %v)", v, v)
	}
	return str + "]"
}
