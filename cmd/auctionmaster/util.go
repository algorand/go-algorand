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

package main

import (
	"io"
	"os"
	"path/filepath"
)

// atomicWriteDir will write [data] into [filename] under [dirpath].
// On crash, either [dirpath/filename] will be untouched (e.g.,
// still does not exist), or it will contain [data].
func atomicWriteDir(dirpath string, filename string, data []byte) error {
	tmpdir := filepath.Join(dirpath, "tmp")
	os.Mkdir(tmpdir, 0777)

	tmpfile := filepath.Join(tmpdir, filename+".tmp")
	f, err := os.OpenFile(tmpfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}

	defer os.Remove(tmpfile)

	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}

	if err1 := f.Sync(); err == nil {
		err = err1
	}

	if err1 := f.Close(); err == nil {
		err = err1
	}

	if err != nil {
		return err
	}

	dirf, err := os.Open(dirpath)
	if err != nil {
		return err
	}

	defer dirf.Close()

	newfile := filepath.Join(dirpath, filename)
	err = os.Rename(tmpfile, newfile)
	if err != nil {
		return err
	}

	err = dirf.Sync()
	if err != nil {
		panic("Could not sync directory, state unknown")
	}

	return nil
}
