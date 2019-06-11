// Copyright (C) 2019 Algorand, Inc.
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
	"fmt"
	"os"

	"github.com/algorand/go-deadlock"
)

// CyclicFileWriter implements the io.Writer interface and wraps an underlying file.
// It ensures that the file never grows over a limit.
type CyclicFileWriter struct {
	mu        deadlock.Mutex
	writer    *os.File
	liveLog   string
	archive   string
	nextWrite uint64
	limit     uint64
}

// MakeCyclicFileWriter returns a writer that wraps a file to ensure it never grows too large
func MakeCyclicFileWriter(liveLogFilePath string, archiveFilePath string, sizeLimitBytes uint64) *CyclicFileWriter {
	cyclic := CyclicFileWriter{writer: nil, liveLog: liveLogFilePath, archive: archiveFilePath, nextWrite: 0, limit: sizeLimitBytes}

	fs, err := os.Stat(liveLogFilePath)
	if err == nil {
		cyclic.nextWrite = uint64(fs.Size())
	}

	writer, err := os.OpenFile(liveLogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("CyclicFileWriter: cannot open log file %v", err))
	}
	cyclic.writer = writer
	return &cyclic
}

// Write ensures the the underlying file can store an additional len(p) bytes. If there is not enough room left it seeks
// to the beginning of the file.
func (cyclic *CyclicFileWriter) Write(p []byte) (n int, err error) {
	cyclic.mu.Lock()
	defer cyclic.mu.Unlock()

	if uint64(len(p)) > cyclic.limit {
		// there's no hope for writing this entry to the log
		return 0, fmt.Errorf("CyclicFileWriter: input too long to write. Len = %v", len(p))
	}

	if cyclic.nextWrite+uint64(len(p)) > cyclic.limit {
		// we don't have enough space to write the entry, so archive data
		cyclic.writer.Close()
		var err error
		if err = os.Rename(cyclic.liveLog, cyclic.archive); err != nil {
			panic(fmt.Sprintf("CyclicFileWriter: cannot archive full log %v", err))
		}
		cyclic.writer, err = os.OpenFile(cyclic.liveLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			panic(fmt.Sprintf("CyclicFileWriter: cannot open log file %v", err))
		}
		cyclic.nextWrite = 0
	}
	// write the data
	n, err = cyclic.writer.Write(p)
	cyclic.nextWrite += uint64(n)
	return
}
