// Copyright (C) 2019-2020 Algorand, Inc.
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
	"syscall"
	"time"
)

// Platform-dependant locker implementation
// How to extend
// 1. Create two new files locker.go and locker_platform.go
// 2. Put appropriate build tags
// 3. Move unixLocker implementation and `newLockedFile` method to locker.go
// 4. Implement platform-specific locker in locker_platform.go
// 5. Ensure `newLockedFile` sets platform-specific locker
//    so that lockedFile.read and lockedFile.write work correctly

type locker interface {
	tryRLock(fd *os.File) error
	tryLock(fd *os.File) error
	unlock(fd *os.File) error
}

type unixLocker struct {
}

func (f *unixLocker) tryRLock(fd *os.File) error {
	return syscall.Flock(int(fd.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
}

func (f *unixLocker) tryLock(fd *os.File) error {
	return syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func (f *unixLocker) unlock(fd *os.File) error {
	return syscall.Flock(int(fd.Fd()), syscall.LOCK_UN)
}

// lockedFile implementation
// It uses non-blocking acquisition with repeats
// and supposed to be platform-agnostic with appropriate locker implementation.
// Each platform needs own specific `newLockedFile`
const maxRepeats = 10
const sleepInterval = 10 * time.Millisecond

type lockedFile struct {
	path   string
	locker locker
}

func newLockedFile(path string) *lockedFile {
	return &lockedFile{
		path:   path,
		locker: &unixLocker{},
	}
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

	lockFunc := func() error { return f.locker.tryRLock(fd) }
	err = attemptLock(lockFunc)
	if err != nil {
		err = fmt.Errorf("Can't acquire lock for %s: %s", f.path, err.Error())
		return
	}
	defer func() {
		err2 := f.locker.unlock(fd)
		if err2 != nil {
			err = err2
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

	lockFunc := func() error { return f.locker.tryLock(fd) }
	err = attemptLock(lockFunc)
	if err != nil {
		return fmt.Errorf("Can't acquire lock for %s: %s", f.path, err.Error())
	}
	defer func() {
		err2 := f.locker.unlock(fd)
		if err2 != nil {
			err = err2
		}
	}()

	err = fd.Truncate(0)
	if err != nil {
		return
	}
	_, err = fd.Write(data)
	return
}

func attemptLock(lockFunc func() error) error {
	var savedError error
	for repeatCounter := 0; repeatCounter < maxRepeats; repeatCounter++ {
		if savedError = lockFunc(); savedError != syscall.EWOULDBLOCK {
			break
		}
		time.Sleep(sleepInterval)
	}
	return savedError
}
