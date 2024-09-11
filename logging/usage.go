// Copyright (C) 2019-2024 Algorand, Inc.
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
	"runtime"
	"sync"
	"time"

	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/metrics"
)

var ramUsageGauge = metrics.MakeGauge(metrics.MetricName{Name: "algod_ram_usage", Description: "number of bytes runtime.ReadMemStats().HeapInuse"})

// UsageLogThread utility logging method
func UsageLogThread(ctx context.Context, log Logger, period time.Duration, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	var now time.Time
	var prevUtime, prevStime int64
	var Utime, Stime int64
	var prevTime time.Time
	var mst runtime.MemStats

	ticker := time.NewTicker(period)
	hasPrev := false

	for true {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}

		now = time.Now()
		Utime, Stime, _ = util.GetCurrentProcessTimes()

		runtime.ReadMemStats(&mst)
		ramUsageGauge.Set(uint64(mst.HeapInuse))

		if hasPrev {
			userNanos := Utime - prevUtime
			sysNanos := Stime - prevStime
			wallNanos := now.Sub(prevTime).Nanoseconds()
			userf := float64(userNanos) / float64(wallNanos)
			sysf := float64(sysNanos) / float64(wallNanos)
			log.Infof("usage nanos wall=%d user=%d sys=%d pu=%0.4f%% ps=%0.4f%% inuse=%d", wallNanos, userNanos, sysNanos, userf*100.0, sysf*100.0, mst.HeapInuse)
		} else {
			hasPrev = true
		}

		prevUtime = Utime
		prevStime = Stime
		prevTime = now
	}
}
