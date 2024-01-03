// Copyright (C) 2019-2024 Algorand, Inc.
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
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	err := New("test")
	assert.Equal(t, "test", err.Error())
}

func TestNewWithPairs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	err := New("test", "a", 7, "b", []byte{3, 4})
	assert.Equal(t, "test", err.Error())
	assert.Equal(t, 7, err.Attrs["a"])
	assert.Equal(t, []byte{3, 4}, err.Attrs["b"])

	err.Msg = ""
	assert.ErrorContains(t, err, `a=7`)
	assert.ErrorContains(t, err, `b="\x03\x04"`)

	err.Msg = "check it: %A"
	assert.ErrorContains(t, err, ` a=7`)
	assert.ErrorContains(t, err, ` b="\x03\x04"`)
	assert.Equal(t, `check it: `, err.Error()[:10])

}

func TestAnnotate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	err := New("test", "a", 7, "b", []byte{3, 4})
	assert.Equal(t, 7, err.Attrs["a"])
	assert.Equal(t, nil, err.Attrs["c"])
	Annotate(err, "c", true, "a", false)
	assert.Equal(t, true, err.Attrs["c"])
	assert.Equal(t, false, err.Attrs["a"])
}

func attribute(err error, name string) any {
	var serr *SError
	if ok := errors.As(err, &serr); ok {
		return serr.Attrs[name]
	}
	return nil
}

func TestAnnotateUnstructured(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	err := errors.New("hello")
	err = Annotate(err, "c", true, "a", false)
	assert.Equal(t, true, attribute(err, "c"))
}

func TestReannotateEmbedded(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var err error
	err = New("test", "a", 7, "b", []byte{3, 4})
	err = fmt.Errorf("embed the above here %w", err)
	assert.Equal(t, 7, attribute(err, "a"))
	assert.Equal(t, nil, attribute(err, "c"))
	Annotate(err, "c", true, "a", false)
	assert.Equal(t, true, attribute(err, "c"))
	assert.Equal(t, false, attribute(err, "a"))
	// "b" is still visible. It would not be is we had _wrapped_ the fmt.Error
	assert.Equal(t, []byte{3, 4}, attribute(err, "b"))
}

func TestWrapBare(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var err error
	err = errors.New("inner thingy")
	err = Wrap(err, "outer stuff", "xxx")
	assert.Equal(t, "inner thingy", attribute(err, "xxx-msg"))
	assert.Equal(t, nil, attribute(err, "xxx-attrs"))
}

func TestWrapStructured(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var err error
	err = New("test", "a", 7, "b", []byte{3, 4})
	err = Wrap(err, "outer stuff", "yyy")
	assert.Equal(t, "test", attribute(err, "yyy-msg"))
	assert.NotNil(t, attribute(err, "yyy-attrs"))

	// these are deeper now, not here
	assert.Equal(t, nil, attribute(err, "a"))
	assert.Equal(t, nil, attribute(err, "b"))

	// here they are
	attrs := attribute(err, "yyy-attrs").(map[string]any)
	assert.Equal(t, 7, attrs["a"])
	assert.Equal(t, []byte{3, 4}, attrs["b"])

	// deeper, with a new attribute
	err = Wrap(err, "further out", "again", "name", "jj")
	assert.Nil(t, attribute(err, "yyy-msg"))
	assert.Equal(t, "outer stuff", attribute(err, "again-msg"))
}
