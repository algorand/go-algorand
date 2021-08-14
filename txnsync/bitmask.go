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
)

var errIndexNotFound = errors.New("invalid bitmask: index not found")
var errInvalidBitmaskType = errors.New("invalid bitmask type")

//msgp:allocbound bitmask maxBitmaskSize
type bitmask []byte

// assumed to be in mode 0, sets bit at index to 1
func (b *bitmask) setBit(index int) {
	byteIndex := index/8 + 1
	(*b)[byteIndex] |= 1 << (index % 8)
}

// trimBitmask compresses the bitmask into one of the 4 types:
// type 0: input bitmask bit pos x b -> output bitmask bit pos x b
// type 1: input bitmask bit pos x b -> output bitmask bit pos x !b
// type 2: stores the positions of bits where the bit value is 1
//         input bitmask first bit 1 at pos A, second bit 1 at pos B, ...
//         output bitmask stores A, B-A, ...
// type 3: same as type 2, but stores the positons where the bit is 0
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

	*b = bytes.TrimRight(*b, "\x00")
}

// iterate through the elements of bitmask without expanding it.
// call the func(entriesCount, setBitIndex) for every set bit
// numTransactions: is the size of the array that transactionIndex is accessing: transactionIndex < numTransactions
// numItems: is the size of the array that itemIndex is accessing: itemIndex < numItems (itemIndex is also the set bit counter)
func (b *bitmask) iterate(numTransactions int, numItems int, callback func(int, int) error) error {
	option := 0
	if len(*b) > 0 {
		option = int((*b)[0])
	} else { // nothing to iterate
		return nil
	}
	itemIndex := 0
	switch option {
	case 0:
		transactionIndex := 0
		maxV := numTransactions / 8
		if numTransactions%8 != 0 {
			maxV++
		}
		maxV++ //b[0] is the option
		if len(*b) > maxV {
			return errIndexNotFound
		}
		for i, v := range (*b)[1:] {
			for ; transactionIndex < numTransactions && v > 0; transactionIndex++ {
				if v&1 != 0 {
					if itemIndex >= numItems {
						return errDataMissing
					}
					if err := callback(transactionIndex, itemIndex); err != nil {
						return err
					}
					itemIndex++
				}
				v >>= 1
			}
			if v > 0 {
				// remaining set bits, but transactionIndex exceeded numTransactions
				return errIndexNotFound
			}
			// in case the loop is cut short because there are no more set bits in the byte
			transactionIndex = (i + 1) * 8
		}
	case 1:
		transactionIndex := 0
		maxV := numTransactions / 8
		if numTransactions%8 != 0 {
			maxV++
		}
		maxV++ //b[0] is the option
		if len(*b) > maxV {
			return errIndexNotFound
		}
		for _, v := range (*b)[1:] {
			// after the first iteration of the loop below, v will be less than 255
			if v >= 255 {
				transactionIndex += 8
				continue
			}
			maxJ := 8
			if maxJ > numTransactions-transactionIndex {
				maxJ = numTransactions - transactionIndex
			}
			for j := 0; j < maxJ; j++ {
				if v&1 == 0 {
					if itemIndex >= numItems {
						return errDataMissing
					}
					if err := callback(transactionIndex, itemIndex); err != nil {
						return err
					}
					itemIndex++
				}
				v >>= 1
				transactionIndex++
			}
			if 255>>maxJ != v {
				// The remaining of the bits must be 1
				return errIndexNotFound
			}
		}
		if numTransactions-transactionIndex > numItems-itemIndex {
			return errDataMissing
		}
		for ; transactionIndex < numTransactions; transactionIndex++ {
			if err := callback(transactionIndex, itemIndex); err != nil {
				return err
			}
			itemIndex++
		}
	case 2:
		sum := 0 // transactionIndex
		elementsCount := (len(*b) - 1) / 2
		if elementsCount > numItems {
			return errDataMissing
		}
		for itemIndex := 0; itemIndex < elementsCount; itemIndex++ {
			sum += int((*b)[itemIndex*2+1])*256 + int((*b)[itemIndex*2+2])
			if sum >= numTransactions {
				return errIndexNotFound
			}
			if err := callback(sum, itemIndex); err != nil {
				return err
			}
		}
	case 3:
		sum := 0
		// This is the least amount of elements can be set.
		// There could be more, if the numbers are corrupted
		// i.e. when sum >= numTransactions
		elementsCount := numTransactions - (len(*b)-1)/2
		if elementsCount > numItems || elementsCount < 0 {
			return errDataMissing
		}
		transactionIndex := 0
		for i := 0; i*2+2 < len(*b); i++ {
			sum += int((*b)[i*2+1])*256 + int((*b)[i*2+2])
			if sum >= numTransactions {
				return errIndexNotFound
			}
			for transactionIndex < sum {
				if err := callback(transactionIndex, itemIndex); err != nil {
					return err
				}
				transactionIndex++
				itemIndex++
			}
			transactionIndex++
		}
		for transactionIndex < numTransactions {
			if err := callback(transactionIndex, itemIndex); err != nil {
				return err
			}
			transactionIndex++
			itemIndex++
		}
	default:
		return errInvalidBitmaskType
	}
	return nil
}

// bytesNeededBitmask returns the number of bytes needed to store entries bits.
func bytesNeededBitmask(entries int) int {
	return (entries+7)/8 + 1
}
