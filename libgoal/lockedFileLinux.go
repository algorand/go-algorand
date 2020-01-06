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

// +build linux

package libgoal

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxLocker struct {
}

// makeLocker create a unix file locker.
// note that the desired way is to use the OFD locker, which locks on the file descriptor level.
// falling back to the non-OFD lock would allow obtaining two locks by the same process. If this becomes
// and issue, we might want to use flock, which wouldn't work across NFS.
func makeLocker() *linuxLocker {
	locker := &linuxLocker{}
	return locker
}

// the FcntlFlock has the most consistent behaviour across platforms,
// and supports both local and network file systems.
func (f *linuxLocker) tryRLock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_RDLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), unix.F_OFD_SETLKW, flock)
}

func (f *linuxLocker) tryLock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), unix.F_OFD_SETLKW, flock)
}

func (f *linuxLocker) unlock(fd *os.File) error {
	flock := &syscall.Flock_t{
		Type:   syscall.F_UNLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd.Fd(), unix.F_OFD_SETLKW, flock)
}
