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

// +build linux

package libgoal

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

type linuxLocker struct {
	setLockWait int
}

// makeLocker create a unix file locker.
// Note that the desired way is to use the OFD locker, which locks on the file descriptor level.
// Since older kernels (Linux kernel < 3.15) do not support OFD, we fall back to non-OFD in that case.
// Falling back to the non-OFD lock would allow obtaining two locks by the same process. If this becomes
// and issue, we might want to use flock, which wouldn't work across NFS on older Linux kernels.
func makeLocker() (*linuxLocker, error) {
	locker := &linuxLocker{}

	// Check whether F_OFD_SETLKW is supported
	getlk := unix.Flock_t{Type: unix.F_RDLCK}
	err := unix.FcntlFlock(0, unix.F_OFD_GETLK, &getlk)
	if err == nil {
		locker.setLockWait = unix.F_OFD_SETLKW
	} else if err == unix.EINVAL {
		// The command F_OFD_SETLKW is not available
		// Fall back to non-OFD locks
		locker.setLockWait = unix.F_SETLKW
	} else {
		// Another unknown error occurred
		return nil, fmt.Errorf("unknown error of FnctlFlock: %v", err)
	}

	return locker, nil
}

// the FcntlFlock has the most consistent behaviour across platforms,
// and supports both local and network file systems.
func (f *linuxLocker) tryRLock(fd *os.File) error {
	flock := &unix.Flock_t{
		Type:   unix.F_RDLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return unix.FcntlFlock(fd.Fd(), f.setLockWait, flock)
}

func (f *linuxLocker) tryLock(fd *os.File) error {
	flock := &unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return unix.FcntlFlock(fd.Fd(), f.setLockWait, flock)
}

func (f *linuxLocker) unlock(fd *os.File) error {
	flock := &unix.Flock_t{
		Type:   unix.F_UNLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	return unix.FcntlFlock(fd.Fd(), f.setLockWait, flock)
}
