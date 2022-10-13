// Copyright (C) 2019-2022 Algorand, Inc.
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

import (
	"fmt"

	"github.com/algorand/msgp/msgp"
)

// serializableError, or state machine error, is a serializable error that
// is correctly written to cadaver files.
//msgp:ignore serializableErrorUnderlying
type serializableErrorUnderlying string

//msgp:ignore serializableError
type serializableError = *serializableErrorUnderlying

func serErrToStr(s serializableError) string {
	if s == nil {
		return ""
	}
	return string(*s)

}

func strToSerErr(s string) (serializableError, error) {
	if s == "" {
		return nil, nil
	}
	e := serializableErrorUnderlying(s)
	return &e, nil

}

//MarshalMsg implements msgp.Marshaler
func (z serializableError) MarshalMsg(b []byte) (o []byte) {
	if z.MsgIsZero() {
		o = msgp.AppendNil(o)
	} else {
		o = msgp.Require(b, z.Msgsize())
		o = msgp.AppendString(o, string(*z))
	}
	return
}

func (*serializableErrorUnderlying) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*serializableErrorUnderlying)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *serializableErrorUnderlying) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zb0001 string
		zb0001, bts, err = msgp.ReadStringBytes(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		(*z) = serializableErrorUnderlying(zb0001)
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z serializableError) Msgsize() (s int) {
	s = msgp.StringPrefixSize
	if z == nil {
		return
	}
	s += len(string(*z))
	return
}

// MsgIsZero returns whether this is a zero value
func (z serializableError) MsgIsZero() bool {
	return z == nil || *z == ""
}

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
