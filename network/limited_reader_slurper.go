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

const allocationStep = 64 * 1024

// LimitedReaderSlurper collects bytes from an io.Reader, but stops if a limit is reached.
type LimitedReaderSlurper struct {
	// Limit is the maximum total bytes that may be read.
	baseAllocation            uint64
	maxExpandBufferAllocation uint64

	baseBuffer   []byte
	expandBuffer []byte
}

// MakeLimitedReaderSlurper creates a LimitedReaderSlurper instance with the provided base and max memory allocations.
func MakeLimitedReaderSlurper(baseAllocation, maxAllocation uint64) *LimitedReaderSlurper {
	if baseAllocation > maxAllocation {
		baseAllocation = maxAllocation
	}
	return &LimitedReaderSlurper{
		baseAllocation:            baseAllocation,
		maxExpandBufferAllocation: maxAllocation - baseAllocation,
	}
}

// Read does repeated Read()s on the io.Reader until it gets io.EOF.
// Returns underlying error or ErrIncomingMsgTooLarge if limit reached.
// Returns a nil error if the underlying io.Reader returned io.EOF.
func (s *LimitedReaderSlurper) Read(reader io.Reader) error {
	if s.baseBuffer == nil {
		s.baseBuffer = make([]byte, 0, s.baseAllocation)
	}

	var readBuffer *[]byte
	for {
		// make sure that we have a buffer to write the data to.
		if len(s.baseBuffer) == cap(s.baseBuffer) {
			// we've already maxed out the base buffer.
			// do we have more space in the expandBuffer ?
			if len(s.expandBuffer) == cap(s.expandBuffer) {
				// we've maxed out the expand buffer.
				// can we expand it ?
				if uint64(len(s.expandBuffer)) < s.maxExpandBufferAllocation {
					newExpandBufferSize := uint64(len(s.expandBuffer) + allocationStep)
					if newExpandBufferSize > s.maxExpandBufferAllocation {
						newExpandBufferSize = s.maxExpandBufferAllocation
					}
					newExpandBuffer := make([]byte, len(s.expandBuffer), newExpandBufferSize)
					copy(newExpandBuffer, s.expandBuffer)
					s.expandBuffer = newExpandBuffer
				} else {
					// the expand buffer already reached capacity.
					return ErrIncomingMsgTooLarge
				}
			}

			// the expand buffer has some more room. use it!
			readBuffer = &s.expandBuffer
		} else {
			// the base buffer isn't full yet. read into it.
			readBuffer = &s.baseBuffer
		}

		n, err := reader.Read(((*readBuffer)[:cap(*readBuffer)])[len(*readBuffer):])
		if err != nil {
			if err == io.EOF {
				*readBuffer = (*readBuffer)[:len(*readBuffer)+n]
				return nil
			}
			return err
		}
		*readBuffer = (*readBuffer)[:len(*readBuffer)+n]
	}
}

// Size returs the current total size of contained chunks read from io.Reader
func (s *LimitedReaderSlurper) Size() uint64 {
	return uint64(len(s.baseBuffer) + len(s.expandBuffer))
}

// Reset clears the buffered data
func (s *LimitedReaderSlurper) Reset() {
	s.expandBuffer = nil
	s.baseBuffer = s.baseBuffer[:0]
}

// Bytes returns a copy of all the collected data
func (s *LimitedReaderSlurper) Bytes() []byte {
	out := make([]byte, len(s.baseBuffer)+len(s.expandBuffer))
	copy(out, s.baseBuffer)
	if len(s.expandBuffer) > 0 {
		copy(out[len(s.baseBuffer):], s.expandBuffer)
	}
	return out
}
