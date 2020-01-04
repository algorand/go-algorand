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
	"io"
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

// the FcntlFlock has the most consistent behaviour across platforms,
// and supports both local and network file systems.
func (f *unixLocker) tryRLock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_RDLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), syscall.F_SETLK, flock)
}

func (f *unixLocker) tryLock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), syscall.F_SETLK, flock)
}

func (f *unixLocker) unlock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_UNLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), syscall.F_SETLK, flock)
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

	lockFunc := func() error { return f.locker.tryLock(fd) }
	err = attemptLock(lockFunc)
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

func attemptLock(lockFunc func() error) error {
	var savedError error
	for repeatCounter := 0; repeatCounter < maxRepeats; repeatCounter++ {
		savedError = lockFunc()
		if savedError != syscall.EACCES && savedError != syscall.EAGAIN && savedError != syscall.EWOULDBLOCK {
			break
		}
		time.Sleep(sleepInterval)
	}
	if savedError != nil {
		fmt.Fprintf(os.Stderr, "already attempted to lock for few times. kept failing.")
		repeatCounter := 0
		for ; repeatCounter < maxRepeats*100; repeatCounter++ {
			savedError = lockFunc()
			if savedError != syscall.EACCES && savedError != syscall.EAGAIN && savedError != syscall.EWOULDBLOCK {
				break
			}
			time.Sleep(sleepInterval)
		}
		if savedError == nil {
			fmt.Fprintf(os.Stderr, "trying for %d more times, did not help !", repeatCounter)
		} else {
			fmt.Fprintf(os.Stderr, "after trying for %d more times, we made it !", repeatCounter)
		}

	}
	return savedError
}
