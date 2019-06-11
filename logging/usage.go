// Copyright (C) 2019 Algorand, Inc.
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

package logging

import (
	"context"
	"sync"
	"syscall"
	"time"
)

func timevalSubToMicroseconds(a, b syscall.Timeval) int64 {
	seconds := a.Sec - b.Sec
	var dusec int32
	if b.Usec > a.Usec {
		seconds--
		dusec = int32(1000000) + int32(a.Usec-b.Usec)
	} else {
		dusec = int32(a.Usec - b.Usec)
	}
	return (int64(seconds) * 1000000) + int64(dusec)
}

// UsageLogThread utility logging method
func UsageLogThread(ctx context.Context, log Logger, period time.Duration, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}
	var usage syscall.Rusage
	var now time.Time
	var prevUsage syscall.Rusage
	var prevTime time.Time
	ticker := time.NewTicker(period)
	hasPrev := false
	for true {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
		now = time.Now()
		err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
		if err != nil {
		}
		if hasPrev {
			userNanos := timevalSubToMicroseconds(usage.Utime, prevUsage.Utime) * 1000
			sysNanos := timevalSubToMicroseconds(usage.Stime, prevUsage.Stime) * 1000
			wallNanos := now.Sub(prevTime).Nanoseconds()
			userf := float64(userNanos) / float64(wallNanos)
			sysf := float64(sysNanos) / float64(wallNanos)
			log.Infof("usage nanos wall=%d user=%d sys=%d pu=%0.4f%% ps=%0.4f%%", wallNanos, userNanos, sysNanos, userf*100.0, sysf*100.0)
		} else {
			hasPrev = true
		}
		prevUsage = usage
		prevTime = now
	}
}
