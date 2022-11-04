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

	"golang.org/x/sys/unix"
)

func getConnRTT(raw syscall.RawConn) (*RTTInfo, error) {
	var info *unix.TCPInfo
	var getSockoptErr error
	err := raw.Control(func(fd uintptr) {
		info, getSockoptErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if err != nil {
		return nil, err
	}
	if getSockoptErr != nil {
		return nil, getSockoptErr
	}
	if info == nil {
		return nil, ErrNoTCPInfo
	}
	return &RTTInfo{
		RTT:    info.Rtt,
		RTTVar: info.Rttvar,
	}, nil
}
