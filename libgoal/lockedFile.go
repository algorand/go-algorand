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

package libgoal

import (
	"fmt"
	"io/ioutil"
	"os"
)

type locker interface {
	tryRLock(fd *os.File) error
	tryLock(fd *os.File) error
	unlock(fd *os.File) error
}

func newLockedFile(path string) (*lockedFile, error) {
	locker, err := makeLocker()
	if err != nil {
		return nil, err
	}
	return &lockedFile{
		path:   path,
		locker: locker,
	}, nil
}

// lockedFile implementation
// It a platform-agnostic with appropriate locker implementation.
// Each platform needs own specific `newLockedFile`

type lockedFile struct {
	path   string
	locker locker
}

func (f *lockedFile) read() (bytes []byte, err error) {
	fd, err := os.Open(f.path)
	if err != nil {
		return
	}
	defer func() {
		err2 := fd.Close()
		if err2 != nil {
			err = err2
		}
	}()

	err = f.locker.tryRLock(fd)
	if err != nil {
		err = fmt.Errorf("Can't acquire read lock for %s: %s", f.path, err.Error())
		return
	}
	defer func() {
		err2 := f.locker.unlock(fd)
		if err2 != nil {
			err = fmt.Errorf("Can't unlock for %s: %s", f.path, err2.Error())
		}
	}()

	bytes, err = ioutil.ReadAll(fd)
	return
}

func (f *lockedFile) write(data []byte, perm os.FileMode) (err error) {
	fd, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return
	}
	defer func() {
		err2 := fd.Close()
		if err2 != nil {
			err = err2
		}
	}()

	err = f.locker.tryLock(fd)
	if err != nil {
		return fmt.Errorf("Can't acquire lock for %s: %s", f.path, err.Error())
	}
	defer func() {
		err2 := f.locker.unlock(fd)
		if err2 != nil {
			err = fmt.Errorf("Can't unlock for %s: %s", f.path, err2.Error())
		}
	}()

	err = fd.Truncate(0)
	if err != nil {
		return
	}
	_, err = fd.Write(data)
	return
}
