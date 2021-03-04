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

// +build windows

package util

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ERROR_INVALID_PARAMETER = syscall.Errno(87)

	processTerminateWaitInMs = 1000
)

// FindProcess looks for a running process by its pid
func FindProcess(pid int) (*os.Process, error) {
	var h syscall.Handle

	process, err := os.FindProcess(pid)
	if err != nil {
		// NOTE: Unlike Unix, Windows tries to open the target process in order to kill it.
		//       ERROR_INVALID_PARAMETER is returned if the process does not exists.
		//       To mimic other OS behavior, if the process does not exist, don't return an error
		var syscallError syscall.Errno

		if errors.As(err, &syscallError) {
			if syscallError == ERROR_INVALID_PARAMETER {
				return nil, nil
			}
		}
		return nil, err
	}

	// If we have a process, check if it is terminated
	h, err = syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err == nil {
		defer func() {
			_ = syscall.CloseHandle(h)
		}()

		ret, e2 := syscall.WaitForSingleObject(h, 0)
		if e2 == nil && ret == syscall.WAIT_OBJECT_0 {
			return nil, nil
		}
	}

	return process, nil
}

// KillProcess kills a running OS process
func KillProcess(pid int, signal os.Signal) error {
	p, err := FindProcess(pid)
	if err == nil {
		if p != nil {
			if signal != syscall.Signal(0) {
				for _, v := range getChildrenProcesses(pid) {
					err2 := v.Kill()
					if err2 == nil {
						waitUntilProcessEnds(v.Pid)
					}
				}

				err = p.Kill()
				waitUntilProcessEnds(p.Pid)
			}
		} else {
			// Signal(0) only checks if we have access to kill a process and if it is really dead
			if p != nil {
				var h syscall.Handle

				h, err = syscall.OpenProcess(syscall.SYNCHRONIZE|syscall.PROCESS_TERMINATE, false, uint32(pid))
				if err == nil {
					ret, e2 := syscall.WaitForSingleObject(h, 0)
					if e2 == nil && ret == syscall.WAIT_OBJECT_0 {
						err = errors.New("os: process already finished")
					}
					_ = syscall.CloseHandle(h)
				}
			} else {
				err = errors.New("os: process already finished")
			}
		}
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
					p, err := FindProcess(int(pe32.ProcessID))
					if err == nil && p != nil {
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

func waitUntilProcessEnds(pid int) {
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err == nil {
		_, _ = syscall.WaitForSingleObject(h, processTerminateWaitInMs)

		_ = syscall.CloseHandle(h)
	}
}