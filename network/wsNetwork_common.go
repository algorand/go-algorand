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

// +build !windows

package network

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func (wn *WebsocketNetwork) rlimitIncomingConnections() error {
	var lim unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim)
	if err != nil {
		return err
	}

	// If rlim_max is not sufficient, reduce IncomingConnectionsLimit
	var rlimitMaxCap uint64
	if lim.Max < wn.config.ReservedFDs {
		rlimitMaxCap = 0
	} else {
		rlimitMaxCap = lim.Max - wn.config.ReservedFDs
	}
	if rlimitMaxCap > uint64(MaxInt) {
		rlimitMaxCap = uint64(MaxInt)
	}
	if wn.config.IncomingConnectionsLimit > int(rlimitMaxCap) {
		wn.log.Warnf("Reducing IncomingConnectionsLimit from %d to %d since RLIMIT_NOFILE is %d",
			wn.config.IncomingConnectionsLimit, rlimitMaxCap, lim.Max)
		wn.config.IncomingConnectionsLimit = int(rlimitMaxCap)
	}

	// Set rlim_cur to match IncomingConnectionsLimit
	newLimit := uint64(wn.config.IncomingConnectionsLimit) + wn.config.ReservedFDs
	if newLimit > lim.Cur {
		if runtime.GOOS == "darwin" && newLimit > 10240 && lim.Max == 0x7fffffffffffffff {
			// The max file limit is 10240, even though
			// the max returned by Getrlimit is 1<<63-1.
			// This is OPEN_MAX in sys/syslimits.h.
			// see https://github.com/golang/go/issues/30401
			newLimit = 10240
		}
		lim.Cur = newLimit
		err = unix.Setrlimit(unix.RLIMIT_NOFILE, &lim)
		if err != nil {
			return err
		}
	}

	return nil
}
