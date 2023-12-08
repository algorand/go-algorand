// Copyright (C) 2019-2023 Algorand, Inc.
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

package serr

import (
	"errors"
	"strings"

	"golang.org/x/exp/slog"
)

type Error struct {
	Msg     string
	Attrs   map[string]any
	Wrapped error
}

// New creates a new structured error object using the supplied message and attributes.
func New(msg string, pairs ...any) *Error {
	attrs := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		attrs[pairs[i].(string)] = pairs[i+1]
	}
	return &Error{Msg: msg, Attrs: attrs}
}

// Error returns error message. It is either the exact supplied message, or the
// serialized attributes if the supplied message was blank.
func (e *Error) Error() string {
	if e.Msg == "" {
		var buf strings.Builder
		args := make([]any, 0, 2*len(e.Attrs))
		for key, val := range e.Attrs {
			args = append(args, key)
			args = append(args, val)
		}
		l := slog.New(slog.NewTextHandler(&buf, nil))
		l.Info("", args)
		return buf.String()
	}
	return e.Msg
}

// Extend adds additional attributes to an existing error. If the supplied error
// is nil, a new structured error is created with the given attributes and no
// message. If the error is not a structured error, it is wrapped in one using
// its existing message and the new attributes.
func Extend(err error, pairs ...any) error {
	if err == nil {
		return New("", pairs...)
	}
	var serr *Error
	if ok := errors.As(err, &serr); ok {
		for i := 0; i < len(pairs); i += 2 {
			serr.Attrs[pairs[i].(string)] = pairs[i+1]
		}
		return err
	}
	return wrap(err, pairs...)
}

// wrap is not exported because it always creates a new structured error. Extend
// is more appropriate from outside the package.
func wrap(err error, pairs ...any) error {
	serr := New(err.Error(), pairs...)
	serr.Wrapped = err
	return serr
}

// Unwrap returns the inner error, if it exists.
func (e *Error) Unwrap() error {
	return e.Wrapped
}
