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

// +build !linux,!windows

package libgoal

import (
	"io"
	"os"
	"syscall"
)

type unixLocker struct {
	setLockWait int
}

// makeLocker create a unix file locker.
// note that the desired way is to use the OFD locker, which locks on the file descriptor level.
// falling back to the non-OFD lock would allow obtaining two locks by the same process. If this becomes
// and issue, we might want to use flock, which wouldn't work across NFS.
func makeLocker() *unixLocker {
	locker := &unixLocker{}
	getlk := syscall.Flock_t{Type: syscall.F_RDLCK}
	if err := syscall.FcntlFlock(0, 36 /*F_OFD_GETLK*/, &getlk); err == nil {
		// constants from /usr/include/bits/fcntl-linux.h
		locker.setLockWait = 38 // F_OFD_SETLKW
	} else {
		locker.setLockWait = syscall.F_SETLKW
	}
	return locker
}

// the FcntlFlock has the most unixLocker behaviour across platforms,
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
	return syscall.FcntlFlock(fd.Fd(), f.setLockWait, flock)
}

func (f *unixLocker) unlock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_UNLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), f.setLockWait, flock)
}
