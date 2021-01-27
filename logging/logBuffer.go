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

package logging

import (
	"bytes"
	"io"

	"github.com/algorand/go-deadlock"
)

type logBuffer struct {
	buffer   []string
	maxDepth uint
	lock     deadlock.Mutex
	first    uint
	used     uint
}

func createLogBuffer(maxDepth uint) *logBuffer {
	return &logBuffer{
		maxDepth: maxDepth,
		buffer:   make([]string, maxDepth),
	}
}

func (b *logBuffer) append(line string) {
	// MaxDepth of 0 means no history is stored
	if b.maxDepth == 0 {
		return
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	// once we reach maxDepth, we switch to cyclic buffer logic.
	if b.used >= b.maxDepth {
		// we've already reached capacity. overwrite the oldest message.
		b.buffer[b.first] = line
		b.first = (b.first + 1) % b.maxDepth
	} else {
		// we haven't reached capacity ( yet )
		b.buffer[(b.first+b.used)%b.maxDepth] = line
		b.used++
	}
}

// trim() will delete the first half of the history; this allows us to reduce redundant log history
// sent when multiple events occur near each other.
func (b *logBuffer) trim() {
	b.lock.Lock()
	defer b.lock.Unlock()

	// Keep only 1/2 of what we've got (rounded up)
	keep := (b.used + 1) / 2

	// Skip over the old entries so there are 'keep' left
	b.first = (b.first + b.used - keep) % b.maxDepth

	// And update used to reflect how many we're keeping
	b.used = keep
}

func (b *logBuffer) string() string {
	if b.maxDepth == 0 {
		return ""
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	var bytesBuffer bytes.Buffer
	for i := uint(0); i < b.used; i++ {
		bytesBuffer.WriteString(b.buffer[(b.first+i)%b.maxDepth])
	}
	return bytesBuffer.String()
}

func (b *logBuffer) wrapOutput(out io.Writer) io.Writer {
	return &writerTee{
		out,
		b,
	}
}

type writerTee struct {
	out       io.Writer
	logBuffer *logBuffer
}

func (writer writerTee) Write(p []byte) (n int, err error) {
	writer.logBuffer.append(string(p))
	return writer.out.Write(p)
}
