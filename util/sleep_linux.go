// Copyright (C) 2019-2022 Algorand, Inc.
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
	"syscall"
	"time"
)

// NanoSleep sleeps for the given d duration.
func NanoSleep(d time.Duration) {
	syscall.Nanosleep(&syscall.Timespec{
		Nsec: d.Nanoseconds() % time.Second.Nanoseconds(),
		Sec:  d.Nanoseconds() / time.Second.Nanoseconds()},
		nil) // nolint:errcheck
}

// NanoAfter waits for the duration to elapse and then sends the current time on the returned channel.
func NanoAfter(d time.Duration) <-chan time.Time {
	// The following is a workaround for the go 1.16 bug, where timers are rounded up to the next millisecond resolution.
	if d > 10*time.Millisecond {
		return time.After(d)
	}
	c := make(chan time.Time, 1)
	go func() {
		NanoSleep(d)
		c <- time.Now()
	}()
	return c
}
