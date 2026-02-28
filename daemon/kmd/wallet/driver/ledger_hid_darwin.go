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
	"runtime"
)

// #include <signal.h>
import "C"

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

	var oldset, newset C.sigset_t
	C.sigemptyset(&newset)
	C.sigaddset(&newset, C.SIGURG)
	C.pthread_sigmask(C.SIG_BLOCK, &newset, &oldset)

	return func() {
		C.pthread_sigmask(C.SIG_SETMASK, &oldset, nil)
		runtime.UnlockOSThread()
	}
}
