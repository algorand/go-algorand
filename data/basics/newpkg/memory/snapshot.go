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
	"fmt"
	"log"
)

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
		log.Panic("For restoring a snapshot u need to save one first!")
	}
	for pointer, value := range sm.savedSnapshots {
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
