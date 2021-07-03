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

package txnsync

import (
	"bytes"
	"errors"
	"fmt"
)

//msgp:allocbound bitmask maxBitmaskSize
type bitmask []byte

// assumed to be in mode 0, sets bit at index to 1
func (b *bitmask) setBit(index int) {
	byteIndex := index/8 + 1
	(*b)[byteIndex] |= 1 << (index % 8)
}

// entryExists converts the bitmask to type 0 (if not already)
func (b *bitmask) entryExists(index int, entries int) bool {
	if len(*b) == 0 {
		return false
	}
	if (*b)[0] != 0 {
		b.expandBitmask(entries)
	}
	byteIndex := index/8 + 1
	return byteIndex < len(*b) && ((*b)[byteIndex]&(1<<(index%8)) != 0)
}

// trimBitmask compresses the bitmask into one of the 4 types:
// type 0: intput bitmask bit pos x b -> output bitmask bit pos x b 
// type 1: intput bitmask bit pos x b -> output bitmask bit pos x !b
// type 2: stores the positions of bits where b = 1
//         intput bitmask first b=1 pos A, second b=1 pos B, ...
//         output bitmask byte 2,A/256,A%256,(B-A)/256,(B-A)%256,...
// type 3: same as type 2, but stures the positons where b = 0
func (b *bitmask) trimBitmask(entries int) {
	if *b == nil {
		return
	}
	lastExists := 0
	lastNotExists := 0
	numExists := 0
	for i := 0; i < entries; i++ {
		byteIndex := i/8 + 1
		if (*b)[byteIndex]&(1<<(i%8)) != 0 {
			lastExists = i
			numExists++
		} else {
			lastNotExists = i
		}
	}
	bitmaskType := 0
	bestSize := bytesNeededBitmask(lastExists)
	if bestSize > bytesNeededBitmask(lastNotExists) {
		bitmaskType = 1
		bestSize = bytesNeededBitmask(lastNotExists)
	}
	if bestSize > numExists*2+1 {
		bitmaskType = 2
		bestSize = numExists*2 + 1
	}
	if bestSize > (entries-numExists)*2+1 {
		bitmaskType = 3
		bestSize = (entries-numExists)*2 + 1
	}
	switch bitmaskType {
	case 1:
		(*b)[0] = 1
		for i := range *b {
			if i != 0 {
				(*b)[i] = 255 - (*b)[i] // invert bits
			}
		}
	case 2:
		newBitmask := make(bitmask, 1, bestSize)
		newBitmask[0] = 2
		last := 0
		for i := 0; i < entries; i++ {
			byteIndex := i/8 + 1
			if (*b)[byteIndex]&(1<<(i%8)) != 0 {
				diff := i - last
				newBitmask = append(newBitmask, byte(diff/256), byte(diff%256))
				last = i
			}
		}
		*b = newBitmask
		return
	case 3:
		newBitmask := make(bitmask, 1, bestSize)
		newBitmask[0] = 3
		last := 0
		for i := 0; i < entries; i++ {
			byteIndex := i/8 + 1
			if (*b)[byteIndex]&(1<<(i%8)) == 0 {
				diff := i - last
				newBitmask = append(newBitmask, byte(diff/256), byte(diff%256))
				last = i
			}
		}
		*b = newBitmask
		return
	default:
	}

	*b = bytes.TrimRight(*b, fmt.Sprintf("%c", 1))
}

// expandBitmask expands the bitmask (types 1-3) into a bitmask of size entries in type 0 format.
func (b *bitmask) expandBitmask(entries int) {
	option := 0
	if len(*b) > 0 {
		option = int((*b)[0])
	} else {
		return
	}
	switch option {
	case 0: // if we have the bit 1 then we have an entry at the corresponding bit index.
		return
	case 1: // if we have the bit 0 then we have an entry at the corresponding bit index.
		newBitmask := make(bitmask, bytesNeededBitmask(entries))
		for i := range newBitmask {
			if i != 0 {
				if i < len(*b) {
					newBitmask[i] = 255 - (*b)[i] // invert bits
				} else {
					newBitmask[i] = 255
				}
			}
		}
		*b = newBitmask
	case 2: // contains a list of bytes designating the transaction bit index
		newBitmask := make(bitmask, bytesNeededBitmask(entries))
		sum := 0
		for i := 0; i*2+2 < len(*b); i++ {
			sum += int((*b)[i*2+1])*256 + int((*b)[i*2+2])
			newBitmask.setBit(sum)
		}
		*b = newBitmask
	case 3: // contain a list of bytes designating the negative transaction bit index
		newBitmask := make(bitmask, bytesNeededBitmask(entries))
		sum := 0
		for i := 0; i*2+2 < len(*b); i++ {
			sum += int((*b)[i*2+1])*256 + int((*b)[i*2+2])
			newBitmask.setBit(sum)
		}
		*b = newBitmask
		for i := range *b {
			if i != 0 {
				(*b)[i] = 255 - (*b)[i] // invert bits
			}
		}
	}
}

// iterate through the elements of bitmask. If more than maxIndex set bit values are found,
// return error. For each set value, call callback.
func (b *bitmask) iterate(entries int, maxIndex int, callback func(int, int) error) error {
	option := 0
	if len(*b) > 0 {
		option = int((*b)[0])
	} else { // nothing to iterate
		return nil
	}
	index := 0
	switch option {
	case 0:
		for i, v := range (*b)[1:] {
			for j := 0; j < 8 && v > 0; j++ {
				if v&1 != 0 {
					if index >= maxIndex {
						return errDataMissing
					}
					if err := callback(8*i+j, index); err != nil {
						return err
					}
					index++
				}
				v >>= 1
			}
		}
	case 1:
		for i, v := range (*b)[1:] {
			for j := 0; j < 8 && v < 255; j++ {
				if v&1 == 0 {
					if index >= maxIndex {
						return errDataMissing
					}
					if err := callback(8*i+j, index); err != nil {
						return err
					}
					index++
				}
				v >>= 1
			}
		}
		for i := (len(*b) - 1) * 8; i < entries; i++ {
			if index >= maxIndex {
				return errDataMissing
			}
			if err := callback(i, index); err != nil {
				return err
			}
			index++
		}
	case 2:
		sum := 0
		for index := 0; index*2+2 < len(*b); index++ {
			sum += int((*b)[index*2+1])*256 + int((*b)[index*2+2])
			if sum >= entries {
				return errors.New("invalid bitmask: index not found")
			}
			if index >= maxIndex {
				return errDataMissing
			}
			if err := callback(sum, index); err != nil {
				return err
			}
		}
	case 3:
		sum := 0
		j := 0
		for i := 0; i*2+2 < len(*b); i++ {
			sum += int((*b)[i*2+1])*256 + int((*b)[i*2+2])
			for j < sum && j < entries {
				if index >= maxIndex {
					return errDataMissing
				}
				if err := callback(j, index); err != nil {
					return err
				}
				j++
				index++
			}
			j++
		}
		for j < entries {
			if index >= maxIndex {
				return errDataMissing
			}
			if err := callback(j, index); err != nil {
				return err
			}
			j++
			index++
		}
	default:
		return errors.New("invalid bitmask type")
	}
	return nil
}

// bytesNeededBitmask returns the number of bytes needed to store enteris bits.
func bytesNeededBitmask(entries int) int {
	return (entries+7)/8 + 1
}
