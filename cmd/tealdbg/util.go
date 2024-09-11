// Copyright (C) 2019-2024 Algorand, Inc.
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

package main

import (
	"strconv"
	"sync/atomic"
)

type atomicString struct {
	value atomic.Value
}

func (s *atomicString) Store(other string) {
	s.value.Store(other)
}

func (s *atomicString) Load() string {
	result := s.value.Load()
	if result != nil {
		if value, ok := result.(string); ok {
			return value
		}
	}
	return ""
}

func (s *atomicString) Length() int {
	return len(s.Load())
}

type atomicBool struct {
	value atomic.Bool
}

func (b *atomicBool) SetTo(other bool) {
	b.value.Store(other)
}

func (b *atomicBool) IsSet() bool {
	return b.value.Load()
}

type atomicInt struct {
	value atomic.Int32
}

func (i *atomicInt) Store(other int) {
	i.value.Store(int32(other))
}

func (i *atomicInt) Load() int {
	return int(i.value.Load())
}

func (i *atomicInt) Add(other int) int {
	return int(i.value.Add(int32(other)))
}

// IsText checks if the input has all printable characters with strconv.IsPrint
func IsText(data []byte) bool {
	printable := true
	for i := 0; i < len(data); i++ {
		if !strconv.IsPrint(rune(data[i])) {
			printable = false
			break
		}
	}
	return printable
}

// IsTextFile checks the input with strconv.IsPrint and for tabs and new lines
func IsTextFile(data []byte) bool {
	printable := true
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if !strconv.IsPrint(rune(ch)) && ch != '\n' && ch != '\r' && ch != '\t' {
			printable = false
			break
		}
	}
	return printable
}
