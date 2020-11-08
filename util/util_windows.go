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

package util

import (
	"errors"
	"syscall"
	"time"
)

/* misc */

// RaiseRlimit increases the number of file descriptors we can have
func RaiseRlimit(_ uint64) error {
	return nil
}

// Getrusage gets file descriptors usage statistics
func Getrusage(who int, rusage *syscall.Rusage) (err error) {
	if rusage != nil {
		*rusage = syscall.Rusage{}
		err = nil
	} else {
		err = errors.New("invalid parameter")
	}
	return
}

// GetCurrentProcessTimes gets current process kernel and usermode times
func GetCurrentProcessTimes() (utime int64, stime int64, err error) {
	var Ktime, Utime syscall.Filetime
	var handle syscall.Handle

	handle, err = syscall.GetCurrentProcess()
	if err == nil {
		err = syscall.GetProcessTimes(handle, nil, nil, &Ktime, &Utime)
	}
	if err == nil {
		utime = filetimeToDuration(&Utime).Nanoseconds()
		stime = filetimeToDuration(&Ktime).Nanoseconds()
	} else {
		utime = 0
		stime = 0
	}
	return
}

func filetimeToDuration(ft *syscall.Filetime) time.Duration {
	n := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime) // in 100-nanosecond intervals
	return time.Duration(n * 100)
}
