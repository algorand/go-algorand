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

package agreement

import "fmt"

// serializableError, or state machine error, is a serializable error that
// is correctly written to cadaver files.
type serializableErrorUnderlying string
type serializableError = *serializableErrorUnderlying

// implement error interface
func (e serializableErrorUnderlying) Error() string {
	return string(e)
}

func (e serializableErrorUnderlying) String() string {
	return e.Error()
}

// makeSerErrStr returns an serializableError that formats as the given text.
func makeSerErrStr(text string) serializableError {
	s := serializableErrorUnderlying(text)
	return &s
}

func makeSerErrf(format string, a ...interface{}) serializableError {
	s := serializableErrorUnderlying(fmt.Sprintf(format, a...))
	return &s
}

// makeSerErr returns an serializableError that formats as the given error.
func makeSerErr(err error) serializableError {
	if err == nil {
		return nil
	}
	s := serializableErrorUnderlying(err.Error())
	return &s
}
