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

package main

import (
	"bytes"
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
	value uint32
}

func (b *atomicBool) SetTo(other bool) {
	var converted uint32 = 0
	if other {
		converted = 1
	}
	atomic.StoreUint32(&b.value, converted)
}

func (b *atomicBool) IsSet() bool {
	return atomic.LoadUint32(&b.value) != 0
}

type atomicInt struct {
	value int32
}

func (i *atomicInt) Store(other int) {
	atomic.StoreInt32(&i.value, int32(other))
}

func (i *atomicInt) Load() int {
	return int(atomic.LoadInt32(&i.value))
}

func (i *atomicInt) Add(other int) int {
	return int(atomic.AddInt32(&i.value, int32(other)))
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

const b64table string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// IntToVLQ writes out value to bytes.Buffer
func IntToVLQ(v int, buf *bytes.Buffer) {
	v <<= 1
	if v < 0 {
		v = -v
		v |= 1
	}
	for v >= 32 {
		buf.WriteByte(b64table[32|(v&31)])
		v >>= 5
	}
	buf.WriteByte(b64table[v])
}

// MakeSourceMapLine creates source map mapping's line entry
func MakeSourceMapLine(tcol, sindex, sline, scol int) string {
	buf := bytes.NewBuffer(nil)
	IntToVLQ(tcol, buf)
	IntToVLQ(sindex, buf)
	IntToVLQ(sline, buf)
	IntToVLQ(scol, buf)
	return buf.String()
}
