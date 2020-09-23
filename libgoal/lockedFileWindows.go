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

// +build windows

package libgoal

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

type windowsLocker struct {
}

var (
	kernel32, _         = syscall.LoadLibrary("kernel32.dll")
	procLockFileEx, _   = syscall.GetProcAddress(kernel32, "LockFileEx")
	procUnlockFileEx, _ = syscall.GetProcAddress(kernel32, "UnlockFileEx")
)

const (
	winLockfileFailImmediately = 0x00000001
	winLockfileExclusiveLock   = 0x00000002
	winLockfileSharedLock      = 0x00000000
)

// makeLocker create a windows file locker.
func makeLocker() (*windowsLocker, error) {
	locker := &windowsLocker{}
	return locker, nil
}

func (f *windowsLocker) tryRLock(fd *os.File) error {
	if errNo := lockFileEx(syscall.Handle(fd.Fd()), winLockfileSharedLock|winLockfileFailImmediately, 0, 1, 0, &syscall.Overlapped{}); errNo > 0 {
		return errors.New("cannot lock file")
	}
	return nil
}

func (f *windowsLocker) tryLock(fd *os.File) error {
	if errNo := lockFileEx(syscall.Handle(fd.Fd()), winLockfileExclusiveLock|winLockfileFailImmediately, 0, 1, 0, &syscall.Overlapped{}); errNo > 0 {
		return errors.New("cannot lock file")
	}
	return nil
}

func (f *windowsLocker) unlock(fd *os.File) error {
	if errNo := unlockFileEx(syscall.Handle(fd.Fd()), 0, 1, 0, &syscall.Overlapped{}); errNo > 0 {
		return errors.New("cannot unlock file")
	}
	return nil
}

func lockFileEx(handle syscall.Handle, flags uint32, reserved uint32, numberOfBytesToLockLow uint32, numberOfBytesToLockHigh uint32, offset *syscall.Overlapped) syscall.Errno {
	r1, _, errNo := syscall.Syscall6(uintptr(procLockFileEx), 6, uintptr(handle), uintptr(flags), uintptr(reserved), uintptr(numberOfBytesToLockLow), uintptr(numberOfBytesToLockHigh), uintptr(unsafe.Pointer(offset)))
	if r1 != 1 {
		if errNo == 0 {
			return syscall.EINVAL
		}
		return errNo
	}
	return 0
}

func unlockFileEx(handle syscall.Handle, reserved uint32, numberOfBytesToLockLow uint32, numberOfBytesToLockHigh uint32, offset *syscall.Overlapped) syscall.Errno {
	r1, _, errNo := syscall.Syscall6(uintptr(procUnlockFileEx), 5, uintptr(handle), uintptr(reserved), uintptr(numberOfBytesToLockLow), uintptr(numberOfBytesToLockHigh), uintptr(unsafe.Pointer(offset)), 0)
	if r1 != 1 {
		if errNo == 0 {
			return syscall.EINVAL
		}
		return errNo
	}
	return 0
}
