// Copyright (C) 2019-2025 Algorand, Inc.
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

package basics

import (
	"errors"
	"maps"
	"strings"

	"golang.org/x/exp/slog"
)

// SError is a structured error object. It contains a message and an arbitrary
// set of attributes. If the message contains "%A", it will be replaced by the
// attributes (in no guaranteed order), when SError() is called.
//
//msgp:ignore SError
type SError struct {
	Msg     string
	Attrs   map[string]any
	Wrapped error
}

// New creates a new structured error object using the supplied message and
// attributes. If the message contains "%A", it will be replaced by the
// attributes when Error() is called.
func New(msg string, pairs ...any) *SError {
	attrs := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		attrs[pairs[i].(string)] = pairs[i+1]
	}
	return &SError{Msg: msg, Attrs: attrs}
}

// Error returns either the exact supplied message, or the serialized attributes if
// the supplied message was blank, or substituted for %A.
func (e *SError) Error() string {
	if e.Msg == "" {
		return e.AttributesAsString()
	}
	// imperfect because we replace \%A as well
	if strings.Contains(e.Msg, "%A") {
		return strings.Replace(e.Msg, "%A", e.AttributesAsString(), -1)
	}
	return e.Msg
}

// AttributesAsString returns the attributes the same way that slog serializes
// attributes to text in a log message, in no guaranteed order.
func (e *SError) AttributesAsString() string {
	var buf strings.Builder
	args := make([]any, 0, 2*len(e.Attrs))
	for key, val := range e.Attrs {
		args = append(args, key)
		args = append(args, val)
	}
	l := slog.New(slog.NewTextHandler(&buf, nil))
	l.Info("", args...)
	return strings.TrimSuffix(strings.SplitN(buf.String(), " ", 4)[3], "\n")
}

// Annotate adds additional attributes to an existing error, even if the error
// is deep in the error chain. If the supplied error is nil, nil is returned so
// that callers can annotate errors without checking if they are non-nil.  If
// the error is not a structured error, it is wrapped in one using its existing
// message and the new attributes. Just like append() for slices, callers should
// re-assign, like this `err = serr.Annotate(err, "x", 100)`
func Annotate(err error, pairs ...any) error {
	if err == nil {
		return nil
	}
	var serr *SError
	if ok := errors.As(err, &serr); ok {
		for i := 0; i < len(pairs); i += 2 {
			serr.Attrs[pairs[i].(string)] = pairs[i+1]
		}
		return err
	}
	// Since we don't have a structured error, we wrap the existing error in one.
	serr = New(err.Error(), pairs...)
	serr.Wrapped = err
	return serr
}

// Wrap is used to "demote" an existing error to a field in a new structured
// error. The wrapped error message is added as $field-msg, and if the error is
// structured, the attributes are added under $field-attrs.
func Wrap(err error, msg string, field string, pairs ...any) error {
	serr := New(msg, field+"-msg", err.Error())
	for i := 0; i < len(pairs); i += 2 {
		serr.Attrs[pairs[i].(string)] = pairs[i+1]
	}
	serr.Wrapped = err

	var inner *SError
	if ok := errors.As(err, &inner); ok {
		attributes := make(map[string]any, len(inner.Attrs))
		maps.Copy(attributes, inner.Attrs)
		serr.Attrs[field+"-attrs"] = attributes
	}

	return serr
}

// Unwrap returns the inner error, if it exists.
func (e *SError) Unwrap() error {
	return e.Wrapped
}

// Attributes returns the attributes of a structured error, or nil/empty.
func Attributes(err error) map[string]any {
	var se *SError
	if errors.As(err, &se) {
		return se.Attrs
	}
	return nil
}
