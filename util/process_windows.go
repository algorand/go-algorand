// Copyright (C) 2019-2020 Algorand, Inc.
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

// +build windows

package util

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// KillProcess kills a running OS process
func KillProcess(pid int, _ os.Signal) error {

	p, err := os.FindProcess(pid)
	if err == nil {

		for _, v := range getChildrenProcesses(pid) {
			_ = v.Kill()
		}

		err = p.Kill()
	}
	return err
}

func getChildrenProcesses(parentPid int) []*os.Process {
	out := []*os.Process{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, uint32(0))
	if err == nil {
		var pe32 windows.ProcessEntry32

		defer windows.CloseHandle(snap)

		pe32.Size = uint32(unsafe.Sizeof(pe32))
		if err := windows.Process32First(snap, &pe32); err == nil {
			for {
				if pe32.ParentProcessID == uint32(parentPid) {
					p, err := os.FindProcess(int(pe32.ProcessID))
					if err == nil {
						out = append(out, p)
					}
				}
				if err = windows.Process32Next(snap, &pe32); err != nil {
					break
				}
			}
		}
	}
	return out
}
