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
	ofd         bool
	setLock     int
	setLockWait int
	getLock     int
}

// makeUnixLocker create a unix file locker.
// note that the desired way is to use the OFD locker, which locks on the file descriptor level.
// falling back to the non-OFD lock would allow obtaining two locks by the same process. If this becomes
// and issue, we might want to use flock, which wouldn't work across NFS.
func makeUnixLocker() *unixLocker {
	locker := &unixLocker{}
	getlk := syscall.Flock_t{Type: syscall.F_RDLCK}
	if err := syscall.FcntlFlock(0, 36 /*F_OFD_GETLK*/, &getlk); err == nil {
		locker.ofd = true
		// constants from /usr/include/bits/fcntl-linux.h
		locker.setLock = 37     // F_OFD_SETLK
		locker.setLockWait = 38 // F_OFD_SETLKW
		locker.getLock = 36     // F_OFD_GETLK
	} else {
		locker.setLock = syscall.F_SETLK
		locker.setLockWait = syscall.F_SETLKW
		locker.getLock = syscall.F_GETLK
	}
	return locker
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
	return syscall.FcntlFlock(fd.Fd(), f.setLockWait, flock)
}

func (f *unixLocker) tryLock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), syscall.F_SETLKW, flock)
}

func (f *unixLocker) unlock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_UNLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), syscall.F_SETLKW, flock)
}

// lockedFile implementation
// It a platform-agnostic with appropriate locker implementation.
// Each platform needs own specific `newLockedFile`

type lockedFile struct {
	path   string
	locker locker
}

func newLockedFile(path string) *lockedFile {
	return &lockedFile{
		path:   path,
		locker: makeUnixLocker(),
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
