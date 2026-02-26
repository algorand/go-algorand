// Copyright (C) 2019-2026 Algorand, Inc.
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

//go:build darwin

package driver

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// maskSIGURG temporarily blocks SIGURG signals during HID operations on macOS.
//
// Go's runtime uses SIGURG for async preemption (goroutine scheduling and GC),
// but this can interfere with macOS IOKit HID calls. When a SIGURG signal is
// delivered during an IOHIDDeviceSetReport call, macOS may return
// kIOReturnError (0xE00002BC), causing the HID operation to fail.
//
// By intercepting SIGURG signals during HID I/O, we prevent the Go runtime's
// async preemption from interrupting the underlying IOKit calls.
//
// Returns a cleanup function that must be called to restore normal signal
// handling. Typical usage:
//
//	cleanup := maskSIGURG()
//	defer cleanup()
//	// ... perform HID operations ...
func maskSIGURG() func() {
	runtime.LockOSThread()
	sigChan := make(chan os.Signal, 10)
	signal.Notify(sigChan, syscall.SIGURG)

	return func() {
		signal.Stop(sigChan)
		close(sigChan)
		runtime.UnlockOSThread()
	}
}
