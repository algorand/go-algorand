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
	"log"
)

type Restorer interface {
	// Restore restores the oldValue for some value inside this Restorer that is specified by 'internalKey'.
	Restore(internalKey string, oldValue interface{})
}

type snapshotKey struct {
	owner       Restorer
	internalKey string
}

type snapshotManager struct {
	pointerSnapshots  map[interface{}]interface{}
	restorerSnapshots map[snapshotKey]interface{}
}

func (sm *snapshotManager) reset() {
	sm.pointerSnapshots = make(map[interface{}]interface{})
	sm.restorerSnapshots = make(map[snapshotKey]interface{})
}

func (sm *snapshotManager) turnOff() {
	sm.pointerSnapshots = nil
	sm.restorerSnapshots = nil
}

func (sm *snapshotManager) restoreSnapshot() {
	// in the current implementation sm.pointerSnapshots and sm.restorerSnapshots will be nil or non-nil at the same type
	if sm.pointerSnapshots == nil {
		log.Panic("For restoring a snapshot u need to save one first!")
	}
	for key, oldValue := range sm.restorerSnapshots {
		key.owner.Restore(key.internalKey, oldValue)
	}
	for pointer, value := range sm.pointerSnapshots {
		switch p := pointer.(type) {
		case *DataType:
			if value == nil {
				*p = nil
			} else {
				*p = value.(DataType)
			}
		case *int:
			*p = value.(int)
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
			log.Panicf("if you are trying to add a new teal.DataType you should add %T support to this function!", p)
		}
	}
}

func (sm *snapshotManager) notifyUpdate(pointer interface{}, oldValue interface{}) {
	// when snapshotManager is turned off this function has no effect.
	if sm.pointerSnapshots == nil {
		return
	}
	if _, exists := sm.pointerSnapshots[pointer]; !exists {
		sm.pointerSnapshots[pointer] = oldValue
	}
}

func (sm *snapshotManager) notifyUpdateWithKey(owner Restorer, internalKey string, oldValue interface{}) {
	if sm.restorerSnapshots == nil {
		return
	}
	key := snapshotKey{owner: owner, internalKey: internalKey}
	if _, exists := sm.restorerSnapshots[key]; !exists {
		sm.restorerSnapshots[key] = oldValue
	}
}

func (sm *snapshotManager) String() string {
	// in the current implementation sm.pointerSnapshots and sm.restorerSnapshots will be nil or non-nil at the same type
	if sm.pointerSnapshots == nil {
		return "<nil>"
	}
	str := "pointers:["
	for _, v := range sm.pointerSnapshots {
		str += fmt.Sprintf("(%T %v)", v, v)
	}
	str += "] keys:["
	for k, v := range sm.restorerSnapshots {
		str += fmt.Sprintf("%v:(%T %v) ", k, v, v)
	}
	return str + "]"
}
