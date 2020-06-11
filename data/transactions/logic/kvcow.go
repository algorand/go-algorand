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

package logic

import (
	"github.com/algorand/go-algorand/data/basics"
)

type keyValueCow struct {
	base  basics.TealKeyValue
	delta basics.StateDelta
}

func makeKeyValueCow(base basics.TealKeyValue, delta basics.StateDelta) *keyValueCow {
	var kvc keyValueCow
	kvc.base = base
	kvc.delta = delta
	return &kvc
}

func (kvc *keyValueCow) read(key string) (value basics.TealValue, ok bool) {
	// If the value for the key has been modified in the delta,
	// then return the modified value.
	valueDelta, ok := kvc.delta[key]
	if ok {
		return valueDelta.ToTealValue()
	}

	// Otherwise, return the value from the underlying key/value.
	value, ok = kvc.base[key]
	return value, ok
}

func (kvc *keyValueCow) write(key string, value basics.TealValue) {
	// If the value being written is identical to the underlying key/value,
	// then ensure there is no delta entry for the key.
	baseValue, ok := kvc.base[key]
	if ok && value == baseValue {
		delete(kvc.delta, key)
	} else {
		// Otherwise, update the delta with the new value.
		kvc.delta[key] = value.ToValueDelta()
	}
}

func (kvc *keyValueCow) del(key string) {
	_, ok := kvc.base[key]
	if ok {
		// If the key already exists in the underlying key/value,
		// update the delta to indicate that the value was deleted.
		kvc.delta[key] = basics.ValueDelta{
			Action: basics.DeleteAction,
		}
	} else {
		// Since the key didn't exist in the underlying key/value,
		// don't include a delta entry for its deletion.
		delete(kvc.delta, key)
	}
}
