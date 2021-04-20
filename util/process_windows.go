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

	STATUS_CANCELLED = uint32(0xC0000120)

	processTerminateWaitInMs = 1000

	killChildsPassCount = 4
)

var (
	errFinishedProcess = errors.New("os: process already finished")
)

// FindProcess looks for a running process by its pid
func FindProcess(pid int) (*os.Process, error) {
	var h syscall.Handle

	process, err := os.FindProcess(pid)
	if err != nil {
		if isInvalidParameterError(err) { // NOTE: See function definition for details
			return nil, nil
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
	} else {
		if isInvalidParameterError(err) { // NOTE: See function definition for details
			return nil, nil
		}
	}

	return process, nil
}

// KillProcess kills a running OS process
func KillProcess(pid int, signal os.Signal) error {
	// Signal(0) only checks if we have access to kill a process and if it is really dead
	if signal == syscall.Signal(0) {
		return isProcessAlive(pid)
	}

	return killProcessTree(pid)
}

func isProcessAlive(pid int) error {
	var ret uint32

	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE|syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		if isInvalidParameterError(err) { // NOTE: See function definition for details
			return errFinishedProcess
		}
		return err
	}
	ret, err = syscall.WaitForSingleObject(h, 0)
	if err == nil && ret == syscall.WAIT_OBJECT_0 {
		err = errFinishedProcess
	}

	_ = syscall.CloseHandle(h)
	return err
}

func killProcessTree(pid int) error {
	err := killProcess(pid)
	if err != nil {
		return err
	}

	// We do several passes just in case the process being killed spawns a new one
	for pass := 1; pass <= killChildsPassCount; pass++ {
		childProcessList := getChildProcesses(pid)
		if len(childProcessList) == 0 {
			break
		}
		for _, childPid := range childProcessList {
			killProcessTree(childPid)
		}
	}

	return nil
}

func getChildProcesses(pid int) []int {
	var pe32 windows.ProcessEntry32

	out := make([]int, 0)

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, uint32(0))
	if err != nil {
		return out
	}

	defer func() {
		_ = windows.CloseHandle(snap)
	}()

	pe32.Size = uint32(unsafe.Sizeof(pe32))
	err = windows.Process32First(snap, &pe32)
	for err != nil {
		if pe32.ParentProcessID == uint32(pid) {
			// Add to list
			out = append(out, int(pe32.ProcessID))
		}

		err = windows.Process32Next(snap, &pe32)
	}

	return out
}

func killProcess(pid int) error {
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE | syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err == nil {
		err = syscall.TerminateProcess(h, STATUS_CANCELLED)
		if err == nil {
			_, _ = syscall.WaitForSingleObject(h, processTerminateWaitInMs)
		}

		_ = syscall.CloseHandle(h)
	}

	return err
}

// NOTE: Unlike Unix, Windows tries to open the target process in order to kill it.
//       ERROR_INVALID_PARAMETER is returned if the process does not exists.
//       To mimic other OS behavior, if the process does not exist, don't return an error
func isInvalidParameterError(err error) bool {
	var syscallError syscall.Errno

	if errors.As(err, &syscallError) {
		if syscallError == ERROR_INVALID_PARAMETER {
			return true
		}
	}
	return false
}
