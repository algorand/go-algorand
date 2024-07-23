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

package util

import (
	"fmt"
	"time"
)

const spinningCursorTickDuration = 100 * time.Millisecond

// RunFuncWithSpinningCursor runs a given function in a go-routine,
// while displaying a spinning cursor to the CLI
func RunFuncWithSpinningCursor(asyncFunc func()) {
	doneChan := make(chan struct{}, 1)
	go func() {
		asyncFunc()
		doneChan <- struct{}{}
	}()

	progressStrings := [...]string{"/", "-", "\\", "|"}

	finished := false
	i := 0
	ticker := time.NewTicker(spinningCursorTickDuration)
	for !finished {
		select {
		case <-doneChan:
			finished = true
			ticker.Stop()
			break
		case <-ticker.C:
			fmt.Print(progressStrings[i])
			fmt.Print("\b")
			i = (i + 1) % len(progressStrings)
		}
	}
}
