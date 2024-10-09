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

//go:build linux

package metrics

import "github.com/jsimonetti/rtnetlink"

func getNetDevStats() ([]netDevStats, error) {
	nds := []netDevStats{}

	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	defer conn.Close()
	links, err := conn.Link.List()
	if err != nil {
		return nil, err
	}

	for _, msg := range links {
		if msg.Attributes == nil {
			continue
		}
		name := msg.Attributes.Name
		stats := msg.Attributes.Stats64
		if stats != nil {
			if stats.RXBytes == 0 && stats.TXBytes == 0 {
				// skip interfaces with no traffic
				continue
			}
			nds = append(nds, netDevStats{
				bytesReceived: stats.RXBytes,
				bytesSent:     stats.TXBytes,
				iface:         name,
			})
		} else if stats32 := msg.Attributes.Stats; stats32 != nil {
			if stats32.RXBytes == 0 && stats32.TXBytes == 0 {
				// skip interfaces with no traffic
				continue
			}
			nds = append(nds, netDevStats{
				bytesReceived: uint64(stats32.RXBytes),
				bytesSent:     uint64(stats32.TXBytes),
				iface:         name,
			})
		}
	}
	return nds, nil
}
