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

package nodecontrol

import (
	"io"
	"os"
	"strings"
	"sync/atomic"
)

// LaggedStdIo is an indirect wrapper around os.Stdin/os.Stdout/os.Stderr that prevents
// direct dependency which could be an issue when a caller panics, leaving the child processes
// alive and blocks for EOF.
type LaggedStdIo struct {
	ioClass    int
	LinePrefix atomic.Value // of datatype string
}

// write responsible for (potentially) splitting the written output into multiple
// lines and adding a prefix for each line.
func (s *LaggedStdIo) write(writer io.Writer, p []byte) (n int, err error) {
	linePrefix := s.LinePrefix.Load().(string)
	// do we have a line prefix ?
	if linePrefix == "" {
		// if not, just write it out.
		return writer.Write(p)
	}
	// break the output buffer into multiple lines.
	lines := strings.Split(string(p), "\n")
	totalBytes := 0
	for _, outputLine := range lines {
		// avoid outputing empty lines.
		if len(outputLine) == 0 {
			continue
		}
		// prepare the line that we want to print
		s := linePrefix + " : " + outputLine + "\n"
		n, err = writer.Write([]byte(s))
		if err != nil {
			return totalBytes + n, err
		}
		totalBytes += n + 1
	}
	// if we success, output the original len(p), so that the caller won't know
	// we've diced and splited the original string.
	return len(p), nil
}

// Write implement the io.Writer interface and redirecting the written output
// to the correct pipe.
func (s *LaggedStdIo) Write(p []byte) (n int, err error) {
	if s.ioClass == 1 {
		return s.write(os.Stdout, p)
	}
	if s.ioClass == 2 {
		return s.write(os.Stderr, p)
	}
	return 0, nil
}

// Read implmenents the io.Reader interface and redirecting the read request to the
// correct stdin pipe.
func (s *LaggedStdIo) Read(p []byte) (n int, err error) {
	if s.ioClass == 0 {
		return os.Stdin.Read(p)
	}
	return 0, nil
}

// SetLinePrefix sets the line prefix that would be used during the write opeearion.
func (s *LaggedStdIo) SetLinePrefix(linePrefix string) {
	s.LinePrefix.Store(linePrefix)
}

// NewLaggedStdIo creates a new instance of the LaggedStdIo.
// allowed stdio are limited to os.Stdin, os.Stdout and os.Stderr
func NewLaggedStdIo(stdio interface{}, linePrefix string) *LaggedStdIo {
	lio := &LaggedStdIo{}
	lio.LinePrefix.Store(linePrefix)
	switch stdio {
	case os.Stdin:
		lio.ioClass = 0
		return lio
	case os.Stdout:
		lio.ioClass = 1
		return lio
	case os.Stderr:
		lio.ioClass = 2
		return lio
	}
	return nil
}
