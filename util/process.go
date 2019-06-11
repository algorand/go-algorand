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
func ExecAndCaptureOutput(command string, args ...string) (string, error) {
	r, w, _ := os.Pipe()

	subcmd := exec.Command(command, args...)
	subcmd.Stdout = w

	err := subcmd.Run()

	w.Close()
	ret, errIO := ioutil.ReadAll(r)

	if err == nil {
		err = errIO
	}
	return string(ret), err
}
