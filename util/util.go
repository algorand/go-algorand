// Copyright (C) 2019-2025 Algorand, Inc.
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

//go:build !windows
// +build !windows

package util

import (
	"fmt"
	"syscall"
)

/* misc */

// GetFdLimits returns a current values for file descriptors limits.
func GetFdLimits() (soft uint64, hard uint64, err error) {
	var rLimit syscall.Rlimit
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return 0, 0, fmt.Errorf("GetFdSoftLimit() err: %w", err)
	}
	return rLimit.Cur, rLimit.Max, nil
}

// RaiseFdSoftLimit raises the file descriptors soft limit to the specified value,
// or leave it unchanged if the value is less than the current.
func RaiseFdSoftLimit(newLimit uint64) error {
	soft, hard, err := GetFdLimits()
	if err != nil {
		return fmt.Errorf("RaiseFdSoftLimit() err: %w", err)
	}
	if newLimit <= soft {
		// Current limit is sufficient; no need to change it.
		return nil
	}
	if newLimit > hard {
		// New limit exceeds the hard limit; set it to the hard limit.
		newLimit = hard
	}
	return SetFdSoftLimit(newLimit)
}

// SetFdSoftLimit sets a new file descriptors soft limit.
func SetFdSoftLimit(newLimit uint64) error {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return fmt.Errorf("SetFdSoftLimit() err: %w", err)
	}

	rLimit.Cur = newLimit
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return fmt.Errorf("SetFdSoftLimit() err: %w", err)
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

// GetTotalMemory gets total system memory
func GetTotalMemory() uint64 {
	return getTotalMemory()
}
