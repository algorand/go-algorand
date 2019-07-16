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

package util

import (
	"io/ioutil"
	"os"
	"os/exec"
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

	err = subcmd.Run()

	wStdout.Close()
	outputStdout, errIO := ioutil.ReadAll(rStdout)
	if err == nil {
		err = errIO
	}

	wStderr.Close()
	outputStderr, errIO := ioutil.ReadAll(rStderr)
	if err == nil {
		err = errIO
	}

	return string(outputStdout), string(outputStderr), err
}
