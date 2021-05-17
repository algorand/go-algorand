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

import "bytes"

//msgp:allocbound bitmask maxBitmaskSize
type bitmask []byte

// assumed to be in mode 0, sets bit at index to 1
func (b *bitmask) SetBit(index int) {
	byteIndex := index/8 + 1
	(*b)[byteIndex] ^= 1 << (index % 8)
}

func (b *bitmask) EntryExists(index int, entries int) bool {
	if len(*b) == 0 {
		return false
	}
	if (*b)[0] != 0 {
		b.expandBitmask(entries)
	}
	byteIndex := index/8 + 1
	return byteIndex < len(*b) && ((*b)[byteIndex]&(1<<(index%8)) != 0)
}

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

	*b = bytes.TrimRight(*b, string(0))
}

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
			newBitmask.SetBit(sum)
		}
		*b = newBitmask
	case 3: // contain a list of bytes designating the negative transaction bit index
		newBitmask := make(bitmask, bytesNeededBitmask(entries))
		sum := 0
		for i := 0; i*2+2 < len(*b); i++ {
			sum += int((*b)[i*2+1])*256 + int((*b)[i*2+2])
			newBitmask.SetBit(sum)
		}
		*b = newBitmask
		for i := range *b {
			if i != 0 {
				(*b)[i] = 255 - (*b)[i] // invert bits
			}
		}
	}
}

func bytesNeededBitmask(elements int) int {
	return (elements+7)/8 + 1
}
