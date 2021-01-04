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

// LimitedReaderSlurper collects bytes from an io.Reader, but stops if a limit is reached.
type LimitedReaderSlurper struct {
	// Limit is the maximum total bytes that may be read.
	Limit uint64

	buf  []byte
	size uint64
}

// Read does repeated Read()s on the io.Reader until it gets io.EOF.
// Returns underlying error or ErrIncomingMsgTooLarge if limit reached.
// Returns a nil error if the underlying io.Reader returned io.EOF.
func (s *LimitedReaderSlurper) Read(reader io.Reader) error {
	if s.buf == nil {
		s.buf = make([]byte, s.Limit+1)
	}

	for s.size <= s.Limit {
		more, err := reader.Read(s.buf[s.size:])
		if err != nil {
			if err == io.EOF {
				s.size += uint64(more)
				return nil
			}
			return err
		}

		s.size += uint64(more)
	}

	return ErrIncomingMsgTooLarge
}

// Size returs the current total size of contained chunks read from io.Reader
func (s *LimitedReaderSlurper) Size() uint64 {
	return s.size
}

// Reset clears the buffered data
func (s *LimitedReaderSlurper) Reset() {
	s.size = 0
}

// Bytes returns a copy of all the collected data
func (s *LimitedReaderSlurper) Bytes() []byte {
	out := make([]byte, s.size)
	copy(out, s.buf)
	return out
}
