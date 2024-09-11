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
	"syscall"

	"golang.org/x/sys/unix"
)

func getConnTCPInfo(raw syscall.RawConn) (*TCPInfo, error) {
	var info *unix.TCPConnectionInfo
	var getSockoptErr error
	err := raw.Control(func(fd uintptr) {
		info, getSockoptErr = unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
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
	return &TCPInfo{
		RTT:     info.Srtt,
		RTTVar:  info.Rttvar,
		SndMSS:  info.Maxseg, // MSS is the same for snd/rcv according bsd/netinet/tcp_usrreq.c
		RcvMSS:  info.Maxseg,
		SndCwnd: info.Snd_cwnd, // Send congestion window
		SndWnd:  info.Snd_wnd,  // Advertised send window
		RcvWnd:  info.Rcv_wnd,  // Advertised recv window
	}, nil
}
