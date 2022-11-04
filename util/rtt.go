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
	"errors"
	"net"
	"syscall"
)

// RTTInfo provides smoothed RTT and RTT variance from socket-level TCP information.
type RTTInfo struct {
	RTT    uint32
	RTTVar uint32
}

var (
	// ErrNotSyscallConn is reported when GetConnRTT is passed a connection that doesn't satisfy the syscall.Conn interface.
	ErrNotSyscallConn = errors.New("conn doesn't satisfy syscall.Conn")
	// ErrRTTUnsupported is reported if TCP information is not available for this platform.
	ErrRTTUnsupported = errors.New("GetConnRTT not supported on this platform")
)

// GetConnRTT returns RTT statistics for a TCP connection collected by the
// underlying network implementation, using a system call on Linux and Mac
// and returning an error for unsupported platforms.
func GetConnRTT(conn net.Conn) (*RTTInfo, error) {
	sysconn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, ErrNotSyscallConn
	}
	raw, err := sysconn.SyscallConn()
	if err != nil {
		return nil, err
	}

	return getConnRTT(raw)
}
