// Copyright (C) 2019-2025 Algorand, Inc.
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
	// remainedUnallocatedSpace is how much more memory we are allowed to allocate for this reader beyond the base allocation.
	remainedUnallocatedSpace uint64

	// currentMessageBytesRead is the size of the message we are currently reading.
	currentMessageBytesRead uint64

	// currentMessageMaxSize is the maximum number of bytes the current message type is allowed to have.
	currentMessageMaxSize uint64

	// the buffers array contain the memory buffers used to store the data. The first level array is preallocated
	// dependening on the desired base allocation. The rest of the levels are dynamically allocated on demand.
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
		currentMessageBytesRead:  0,
		currentMessageMaxSize:    0,
		buffers:                  make([][]byte, 1+(maxAllocation-baseAllocation+allocationStep-1)/allocationStep),
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
				// we ran out of memory, but is there any more data ?
				n, err := reader.Read(make([]byte, 1))
				switch {
				case n > 0:
					// yes, there was at least one extra byte - return ErrIncomingMsgTooLarge
					return ErrIncomingMsgTooLarge
				case err == io.EOF:
					// no, no more data. just return nil
					return nil
				case err == nil:
					// if we received err == nil and n == 0, we should retry calling the Read function.
					continue
				default:
					// if we received a non-io.EOF error, return it.
					return err
				}
			}

			// make another buffer
			s.allocateNextBuffer()
		}

		readBuffer = s.buffers[s.lastBuffer]
		// the entireBuffer is the same underlying buffer as readBuffer, but the length was moved to the maximum buffer capacity.
		entireBuffer := readBuffer[:cap(readBuffer)]
		// read the data into the unused area of the read buffer.
		n, err := reader.Read(entireBuffer[len(readBuffer):])
		s.currentMessageBytesRead += uint64(n)
		if s.currentMessageMaxSize > 0 && s.currentMessageBytesRead > s.currentMessageMaxSize {
			return ErrIncomingMsgTooLarge
		}
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

// Reset clears the buffered data and sets a limit for the upcoming message
func (s *LimitedReaderSlurper) Reset(n uint64) {
	for i := 1; i <= s.lastBuffer; i++ {
		s.remainedUnallocatedSpace += uint64(cap(s.buffers[i]))
		s.buffers[i] = nil
	}
	s.currentMessageMaxSize = n
	s.currentMessageBytesRead = 0
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

// allocateNextBuffer allocates the next buffer and places it in the buffers array.
func (s *LimitedReaderSlurper) allocateNextBuffer() {
	s.lastBuffer++
	allocationSize := min(allocationStep, s.remainedUnallocatedSpace)
	s.buffers[s.lastBuffer] = make([]byte, 0, allocationSize)
	s.remainedUnallocatedSpace -= allocationSize
}
