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

package driver

import (
	"encoding/binary"
	"fmt"

	"github.com/karalabe/hid"
)

const ledgerVendorID = 0x2c97

// LedgerUSB is a wrapper around a Ledger USB HID device, used to implement
// the protocol used for sending messages to the application running on the
// Ledger hardware wallet.
type LedgerUSB struct {
	hiddev *hid.Device
}

// LedgerUSBError is a wrapper around the two-byte error code that the Ledger
// protocol returns.
type LedgerUSBError uint16

// Error satisfies builtin interface `error`
func (err LedgerUSBError) Error() string {
	return fmt.Sprintf("Exchange: unexpected status 0x%x", uint16(err))
}

// Protocol reference:
// https://github.com/LedgerHQ/blue-loader-python/blob/master/ledgerblue/comm.py (see HIDDongleHIDAPI)
// https://github.com/LedgerHQ/blue-loader-python/blob/master/ledgerblue/ledgerWrapper.py (see wrapCommandAPDU)

// WritePackets sends a message to the Ledger device, by breaking it up
// into multiple packets as needed.
func (l *LedgerUSB) WritePackets(msg []byte) error {
	first := true
	sequenceIdx := 0
	offset := 0

	if len(msg) >= 1<<16 {
		return fmt.Errorf("WritePackets: message too long (%d)", len(msg))
	}

	for {
		var packet [64]byte
		cur := packet[:]

		binary.BigEndian.PutUint16(cur, 0x0101)
		cur = cur[2:]

		cur[0] = 0x05
		cur = cur[1:]

		binary.BigEndian.PutUint16(cur, uint16(sequenceIdx))
		cur = cur[2:]

		if first {
			binary.BigEndian.PutUint16(cur, uint16(len(msg)))
			cur = cur[2:]
			first = false
		}

		copied := copy(cur, msg[offset:])

		cc, err := l.hiddev.Write(packet[:])
		if err != nil {
			return err
		}
		if cc != len(packet) {
			return fmt.Errorf("WritePackets: short write: %d != %d", cc, len(packet))
		}

		sequenceIdx++
		offset += copied

		if offset >= len(msg) {
			// Nothing more to send
			break
		}
	}

	return nil
}

// ReadPackets reads a message from the Ledger device, assembling multiple
// packets as needed.
func (l *LedgerUSB) ReadPackets() ([]byte, error) {
	first := true
	sequenceIdx := 0
	var dataleft uint16
	var msg []byte

	for {
		var packet [64]byte
		cc, err := l.hiddev.Read(packet[:])
		if err != nil {
			return nil, err
		}
		if cc != len(packet) {
			return nil, fmt.Errorf("ReadPackets: short read: %d != %d", cc, len(packet))
		}

		cur := packet[:]

		channel := binary.BigEndian.Uint16(cur)
		cur = cur[2:]
		if channel != 0x0101 {
			return nil, fmt.Errorf("ReadPackets: wrong channel %x", channel)
		}

		if cur[0] != 0x05 {
			return nil, fmt.Errorf("ReadPackets: wrong tag %x", cur[0])
		}
		cur = cur[1:]

		seq := binary.BigEndian.Uint16(cur)
		cur = cur[2:]
		if seq != uint16(sequenceIdx) {
			return nil, fmt.Errorf("ReadPackets: wrong seq %d", seq)
		}

		if first {
			dataleft = binary.BigEndian.Uint16(cur)
			cur = cur[2:]
			first = false
		}

		if dataleft < uint16(len(cur)) {
			msg = append(msg, cur[:dataleft]...)
			dataleft = 0
		} else {
			msg = append(msg, cur...)
			dataleft -= uint16(len(cur))
		}

		sequenceIdx++

		if dataleft == 0 {
			// Nothing more to receive
			break
		}
	}

	return msg, nil
}

// Exchange sends a message to the Ledger device, waits for a response,
// and returns the response data.
func (l *LedgerUSB) Exchange(msg []byte) ([]byte, error) {
	err := l.WritePackets(msg)
	if err != nil {
		return nil, err
	}

	reply, err := l.ReadPackets()
	if err != nil {
		return nil, err
	}

	if len(reply) < 2 {
		return nil, fmt.Errorf("Exchange: reply too short: %d < 2", len(reply))
	}

	replyMsg := reply[:len(reply)-2]
	replyStat := binary.BigEndian.Uint16(reply[len(reply)-2:])
	replyStatHi := replyStat & 0xff00
	if replyStat != 0x9000 && replyStatHi != 0x6100 && replyStatHi != 0x6c00 {
		// See various hints about what the error status might mean in
		// HIDDongleHIDAPI.exchange():
		// https://github.com/LedgerHQ/blue-loader-python/blob/master/ledgerblue/comm.py
		return nil, LedgerUSBError(replyStat)
	}

	return replyMsg, nil
}

// USBInfo returns information about the underlying USB device.
func (l *LedgerUSB) USBInfo() hid.DeviceInfo {
	return l.hiddev.DeviceInfo
}

// LedgerEnumerate returns all of the Ledger devices connected to this machine.
func LedgerEnumerate() ([]hid.DeviceInfo, error) {
	if !hid.Supported() {
		return nil, fmt.Errorf("HID not supported")
	}

	var infos []hid.DeviceInfo
	for _, info := range hid.Enumerate(ledgerVendorID, 0) {
		infos = append(infos, info)
	}

	return infos, nil
}
