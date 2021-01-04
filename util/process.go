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

package util

import (
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// ExecAndCaptureOutput runs the specified command and args and captures
// stdout into a string, returning the string or an error upon completion.
func ExecAndCaptureOutput(command string, args ...string) (string, string, error) {
	rStdout, wStdout, err := os.Pipe()
	if err != nil {
		return "", "", err
	}
	rStderr, wStderr, err := os.Pipe()
	if err != nil {
		return "", "", err
	}

	subcmd := exec.Command(command, args...)
	subcmd.Stdout = wStdout
	subcmd.Stderr = wStderr

	outputStdout := make([]byte, 0, 10240)
	outputStderr := make([]byte, 0, 1024)

	var wg sync.WaitGroup
	wg.Add(2)

	reader := func(input *os.File, output *[]byte) {
		defer wg.Done()

		for {
			buf := make([]byte, 1024)
			read, e := input.Read(buf)
			if e == io.EOF {
				break
			}
			if read > 0 {
				*output = append(*output, buf[0:read]...)
			} else {
				time.Sleep(time.Microsecond)
			}
		}
	}
	go reader(rStdout, &outputStdout)
	go reader(rStderr, &outputStderr)

	err = subcmd.Run()
	wStdout.Close()
	wStderr.Close()

	wg.Wait()

	return string(outputStdout), string(outputStderr), err
}
