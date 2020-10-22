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

// +build !windows

package util

import (
	"syscall"
)

/* misc */

// RaiseRlimit increases the number of file descriptors we can have
func RaiseRlimit(amount uint64) error {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return err
	}

	rLimit.Cur = amount
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return err
	}
	return nil
}

// Getrusage gets file descriptors usage statistics
func Getrusage(who int, rusage *syscall.Rusage) (err error) {
	err = syscall.Getrusage(who, rusage)
	return
}

// GetCurrentProcessTimes gets current process kernel and usermode times
func GetCurrentProcessTimes() (utime int64, stime int64, err error) {
	var usage syscall.Rusage

	err = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	if err == nil {
		utime = usage.Utime.Nano()
		stime = usage.Stime.Nano()
	} else {
		utime = 0
		stime = 0
	}
	return
}
