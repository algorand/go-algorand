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

package logic

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
)

type keyValueCow struct {
	base  basics.TealKeyValue
	delta basics.StateDelta

	maxSchema  basics.StateSchema
	calcSchema basics.StateSchema

	maxKeyLen int
	maxValLen int
}

func makeKeyValueCow(base basics.TealKeyValue, delta basics.StateDelta, maxSchema basics.StateSchema, proto *config.ConsensusParams) (*keyValueCow, error) {
	var kvc keyValueCow
	var err error

	if proto == nil {
		return nil, fmt.Errorf("got nil consensus params in kvcow")
	}

	if delta == nil {
		return nil, fmt.Errorf("got nil delta in kvcow")
	}

	kvc.base = base
	kvc.delta = delta
	kvc.maxSchema = maxSchema
	kvc.maxKeyLen = proto.MaxAppKeyLen
	kvc.maxValLen = proto.MaxAppBytesValueLen

	kvc.calcSchema, err = base.ToStateSchema()
	if err != nil {
		return nil, err
	}

	// Check that the backing map is compliant with the consensus params
	err = kvc.checkSchema()
	if err != nil {
		return nil, err
	}

	return &kvc, nil
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

func (kvc *keyValueCow) write(key string, value basics.TealValue) error {
	// Enforce maximum key length
	if len(key) > kvc.maxKeyLen {
		return fmt.Errorf("key too long: length was %d, maximum is %d", len(key), kvc.maxKeyLen)
	}

	// Enforce maximum value length
	if value.Type == basics.TealBytesType && len(value.Bytes) > kvc.maxValLen {
		return fmt.Errorf("value too long for key 0x%x: length was %d, maximum is %d", key, len(value.Bytes), kvc.maxValLen)
	}

	// Keep track of old value for updating counts
	beforeValue, beforeOk := kvc.read(key)

	// If the value being written is identical to the underlying key/value,
	// then ensure there is no delta entry for the key.
	baseValue, ok := kvc.base[key]
	if ok && value == baseValue {
		delete(kvc.delta, key)
	} else {
		// Otherwise, update the delta with the new value.
		kvc.delta[key] = value.ToValueDelta()
	}

	// Keep track of new value for updating counts
	afterValue, afterOk := kvc.read(key)
	err := kvc.updateSchema(beforeValue, beforeOk, afterValue, afterOk)
	if err != nil {
		return err
	}
	return kvc.checkSchema()
}

func (kvc *keyValueCow) del(key string) error {
	// Keep track of old value for updating counts
	beforeValue, beforeOk := kvc.read(key)

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

	// Keep track of new value for updating counts. Technically a delete
	// can never cause a schema violation, but for let's return an error
	// type for functions that can modify the cow
	afterValue, afterOk := kvc.read(key)
	err := kvc.updateSchema(beforeValue, beforeOk, afterValue, afterOk)
	if err != nil {
		return err
	}
	return kvc.checkSchema()
}

func (kvc *keyValueCow) updateSchema(bv basics.TealValue, bok bool, av basics.TealValue, aok bool) error {
	// If the value existed before, decrement the count of the old type.
	if bok {
		switch bv.Type {
		case basics.TealBytesType:
			kvc.calcSchema.NumByteSlice--
		case basics.TealUintType:
			kvc.calcSchema.NumUint--
		default:
			return fmt.Errorf("unknown before type: %v", bv.Type)
		}
	}

	// If the value exists now, increment the count of the new type.
	if aok {
		switch av.Type {
		case basics.TealBytesType:
			kvc.calcSchema.NumByteSlice++
		case basics.TealUintType:
			kvc.calcSchema.NumUint++
		default:
			return fmt.Errorf("unknown after type: %v", av.Type)
		}
	}
	return nil
}

func (kvc *keyValueCow) checkSchema() error {
	// Check against the max schema
	if kvc.calcSchema.NumUint > kvc.maxSchema.NumUint {
		return fmt.Errorf("store integer count %d exceeds schema integer count %d", kvc.calcSchema.NumUint, kvc.maxSchema.NumUint)
	}
	if kvc.calcSchema.NumByteSlice > kvc.maxSchema.NumByteSlice {
		return fmt.Errorf("store bytes count %d exceeds schema bytes count %d", kvc.calcSchema.NumByteSlice, kvc.maxSchema.NumByteSlice)
	}
	return nil
}
