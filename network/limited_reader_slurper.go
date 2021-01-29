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

package network

import (
	"errors"
	"io"
)

// ErrIncomingMsgTooLarge is returned when an incoming message is too large
var ErrIncomingMsgTooLarge = errors.New("read limit exceeded")

// allocationStep is the amount of memory allocated at any single time we don't have enough memory allocated.
const allocationStep = uint64(64 * 1024)

// LimitedReaderSlurper collects bytes from an io.Reader, but stops if a limit is reached.
type LimitedReaderSlurper struct {
	// remainedUnallocatedSpace is how much more memory we are allowed to allocate for this reader.
	remainedUnallocatedSpace uint64

	// the buffers array contain the memory buffers used to store the data. The first level array is preallocated
	// dependening on the max desired allocation.
	buffers [][]byte

	// lastBuffer is the index of the last filled buffer, or the first one if no buffer was ever filled.
	lastBuffer int
}

// MakeLimitedReaderSlurper creates a LimitedReaderSlurper instance with the provided base and max memory allocations.
func MakeLimitedReaderSlurper(baseAllocation, maxAllocation uint64) *LimitedReaderSlurper {
	if baseAllocation > maxAllocation {
		baseAllocation = maxAllocation
	}
	lrs := &LimitedReaderSlurper{
		remainedUnallocatedSpace: maxAllocation - baseAllocation,
		lastBuffer:               0,
		buffers:                  make([][]byte, 1+(maxAllocation-baseAllocation+allocationStep)/allocationStep),
	}
	lrs.buffers[0] = make([]byte, 0, baseAllocation)
	return lrs
}

// Read does repeated Read()s on the io.Reader until it gets io.EOF.
// Returns underlying error or ErrIncomingMsgTooLarge if limit reached.
// Returns a nil error if the underlying io.Reader returned io.EOF.
func (s *LimitedReaderSlurper) Read(reader io.Reader) error {
	var readBuffer []byte
	for {
		// do we have more room in the current buffer ?
		if len(s.buffers[s.lastBuffer]) == cap(s.buffers[s.lastBuffer]) {
			// current buffer is full, try to expand buffers
			if s.remainedUnallocatedSpace == 0 {
				// we ran out of memory
				return ErrIncomingMsgTooLarge
			}
			// make another buffer
			s.lastBuffer++
			allocationSize := allocationStep
			if allocationSize > s.remainedUnallocatedSpace {
				allocationSize = s.remainedUnallocatedSpace
			}
			s.buffers[s.lastBuffer] = make([]byte, 0, allocationSize)
			s.remainedUnallocatedSpace -= allocationSize
		}

		readBuffer = s.buffers[s.lastBuffer]
		n, err := reader.Read((readBuffer[:cap(readBuffer)])[len(readBuffer):])
		if err != nil {
			if err == io.EOF {
				s.buffers[s.lastBuffer] = readBuffer[:len(readBuffer)+n]
				return nil
			}
			return err
		}
		s.buffers[s.lastBuffer] = readBuffer[:len(readBuffer)+n]
	}
}

// Size returs the current total size of contained chunks read from io.Reader
func (s *LimitedReaderSlurper) Size() (size uint64) {
	for i := 0; i <= s.lastBuffer; i++ {
		size += uint64(len(s.buffers[i]))
	}
	return
}

// Reset clears the buffered data
func (s *LimitedReaderSlurper) Reset() {
	for i := 1; i <= s.lastBuffer; i++ {
		s.remainedUnallocatedSpace += uint64(cap(s.buffers[i]))
		s.buffers[i] = nil
	}
	s.buffers[0] = s.buffers[0][:0]
	s.lastBuffer = 0
}

// Bytes returns a copy of all the collected data
func (s *LimitedReaderSlurper) Bytes() []byte {
	out := make([]byte, s.Size())
	offset := 0
	for i := 0; i <= s.lastBuffer; i++ {
		copy(out[offset:], s.buffers[i])
		offset += len(s.buffers[i])
	}
	return out
}
