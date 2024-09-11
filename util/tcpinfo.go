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
	"errors"
	"net"
	"syscall"
)

// TCPInfo provides socket-level TCP information.
type TCPInfo struct {
	RTT            uint32 `json:",omitempty"` // smoothed RTT
	RTTVar         uint32 `json:",omitempty"` // RTT variance
	RTTMin         uint32 `json:",omitempty"` // smallest observed RTT on the connection
	SndMSS, RcvMSS uint32 `json:",omitempty"` // send and receive maximum segment size
	SndCwnd        uint32 `json:",omitempty"` // sender congestion window
	SndWnd         uint32 `json:",omitempty"` // send window advertised to receiver
	RcvWnd         uint32 `json:",omitempty"` // receive window advertised to sender
	//  tcpi_delivery_rate: The most recent goodput, as measured by
	//    tcp_rate_gen(). If the socket is limited by the sending
	//    application (e.g., no data to send), it reports the highest
	//    measurement instead of the most recent. The unit is bytes per
	//    second (like other rate fields in tcp_info).
	Rate uint64 `json:",omitempty"`
	//  tcpi_delivery_rate_app_limited: A boolean indicating if the goodput
	//    was measured when the socket's throughput was limited by the
	//    sending application.
	AppLimited bool `json:",omitempty"`
}

var (
	// ErrNotSyscallConn is reported when GetConnTCPInfo is passed a connection that doesn't satisfy the syscall.Conn interface.
	ErrNotSyscallConn = errors.New("conn doesn't satisfy syscall.Conn")
	// ErrTCPInfoUnsupported is reported if TCP information is not available for this platform.
	ErrTCPInfoUnsupported = errors.New("GetConnRTT not supported on this platform")
	// ErrNoTCPInfo is reported if getsockopt returned no TCP info for some reason.
	ErrNoTCPInfo = errors.New("getsockopt returned no TCP info")
)

// GetConnTCPInfo returns statistics for a TCP connection collected by the
// underlying network implementation, using a system call on Linux and Mac
// and returning an error for unsupported platforms.
func GetConnTCPInfo(conn net.Conn) (*TCPInfo, error) {
	if conn == nil {
		return nil, ErrNotSyscallConn
	}
	sysconn, ok := conn.(syscall.Conn)
	if sysconn == nil || !ok {
		return nil, ErrNotSyscallConn
	}
	raw, err := sysconn.SyscallConn()
	if err != nil {
		return nil, err
	}

	return getConnTCPInfo(raw)
}
