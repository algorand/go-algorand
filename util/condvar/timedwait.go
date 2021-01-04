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

package condvar

import (
	"sync"
	"sync/atomic"
	"time"
)

// TimedWait waits for sync.Cond c to be signaled, with a timeout.
// If the condition is not signaled before timeout, TimedWait forces
// a Broadcast() on c until this function returns.  This assumes a
// (common) use of sync.Cond where stray signals are allowed, so
// the extra Broadcast() introduced by this function isn't a problem.
// This function does not indicate whether a timeout occurred or not;
// the caller should check time.Now() as needed.
func TimedWait(c *sync.Cond, timeout time.Duration) {
	var done int32

	go func() {
		<-time.After(timeout)

		for atomic.LoadInt32(&done) == 0 {
			c.Broadcast()

			// It is unlikely but possible that the parent
			// thread hasn't gotten around to calling c.Wait()
			// yet, so the c.Broadcast() did not wake it up.
			// Sleep for a second and check again.
			<-time.After(time.Second)
		}
	}()

	c.Wait()
	atomic.StoreInt32(&done, 1)
}
