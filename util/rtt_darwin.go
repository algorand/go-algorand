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
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func getConnRTT(conn net.Conn) (*RTTInfo, error) {
	sysconn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, ErrNotSyscallConn
	}
	raw, err := sysconn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var info *unix.TCPConnectionInfo
	var getSockoptErr error
	err = raw.Control(func(fd uintptr) {
		info, getSockoptErr = unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	})
	if err != nil {
		return nil, err
	}
	if getSockoptErr != nil {
		return nil, getSockoptErr
	}
	var ret RTTInfo
	if info != nil {
		ret.RTT = uint64(info.Srtt)
		ret.RTTVar = uint64(info.Rttvar)
	}
	return &ret, nil
}
