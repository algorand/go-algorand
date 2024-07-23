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
	"unsafe"

	"golang.org/x/sys/unix"
)

func getConnTCPInfo(raw syscall.RawConn) (*TCPInfo, error) {
	var info linuxTCPInfo
	size := unsafe.Sizeof(info)

	var errno syscall.Errno
	err := raw.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_INFO,
			uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil {
		return nil, err
	}
	if errno != 0 {
		return nil, errno
	}
	if info == (linuxTCPInfo{}) {
		return nil, ErrNoTCPInfo
	}
	return &TCPInfo{
		RTT:        info.rtt,
		RTTVar:     info.rttvar,
		RTTMin:     info.min_rtt,
		SndMSS:     info.snd_mss,
		RcvMSS:     info.rcv_mss,
		SndCwnd:    info.snd_cwnd, // Send congestion window
		RcvWnd:     info.snd_wnd,  // "tp->snd_wnd, the receive window that the receiver has advertised to the sender."
		Rate:       info.delivery_rate,
		AppLimited: bool((info.app_limited >> 7) != 0), // get first bit
	}, nil
}

// linuxTCPInfo is based on linux include/uapi/linux/tcp.h struct tcp_info
//
//revive:disable:var-naming
//nolint:structcheck // complains about unused fields that are rqeuired to match C tcp_info struct
type linuxTCPInfo struct {
	state       uint8
	ca_state    uint8
	retransmits uint8
	probes      uint8
	backoff     uint8
	options     uint8
	wscale      uint8 // __u8 tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	app_limited uint8 // __u8 tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2;

	rto     uint32
	ato     uint32
	snd_mss uint32
	rcv_mss uint32

	unacked uint32
	sacked  uint32
	lost    uint32
	retrans uint32
	fackets uint32

	last_data_sent uint32
	last_ack_sent  uint32
	last_data_recv uint32
	last_ack_recv  uint32

	pmtu         uint32
	rcv_ssthresh uint32
	rtt          uint32
	rttvar       uint32
	snd_ssthresh uint32
	snd_cwnd     uint32
	advmss       uint32
	reordering   uint32

	rcv_rtt   uint32
	rcv_space uint32

	total_retrans uint32

	// extended info beyond what's in syscall.TCPInfo
	pacing_rate     uint64
	max_pacing_rate uint64
	byte_acked      uint64
	bytes_received  uint64
	segs_out        uint32
	segs_in         uint32

	notsent_bytes uint32
	min_rtt       uint32
	data_segs_in  uint32
	data_segs_out uint32

	delivery_rate uint64

	busy_time      uint64
	rwnd_limited   uint64
	sndbuf_limited uint64

	delivered    uint32
	delivered_ce uint32

	bytes_sent    uint64
	bytes_retrans uint64
	dsack_dups    uint32
	reord_seen    uint32

	rcv_ooopack uint32

	snd_wnd uint32
}
