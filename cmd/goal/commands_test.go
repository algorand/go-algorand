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

package main

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureDataDirReturnsWhenDataDirIsProvided(t *testing.T) {
	expectedDir := "~/.algorand"
	os.Setenv("ALGORAND_DATA", expectedDir)
	actualDir := ensureFirstDataDir()
	require.Equal(t, expectedDir, actualDir)
}

func TestEnsurePasswordWhenEnvironmentVariableIsProvided(t *testing.T) {
	expectedPassword := []byte("password")
	os.Setenv("ALGORAND_KMD_PASSWORD", string(expectedPassword))
	actualPassword := ensurePassword()
	require.Equal(t, expectedPassword, actualPassword)
}

func TestEnsurePasswordWhenEnvironmentVariableIsProvidedButIncorrect(t *testing.T) {
	incorrectPassword := []byte("incorrectpassword")
	os.Setenv("ALGORAND_KMD_PASSWORD", "password")
	actualPassword := ensurePassword()
	require.NotEqual(t, incorrectPassword, actualPassword)
}

func TestEnsurePasswordWhenEnvironmentVariableIsNotProvided(t *testing.T) {
	if err := os.Unsetenv("ALGORAND_KMD_PASSWORD"); err != nil {
		require.Error(t, err)
	}
	if os.Getenv("REAL_TEST") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=TestEnsurePasswordWhenEnvironmentVariableIsNotProvided")
		cmd.Env = append(os.Environ(), "REAL_TEST=1")
		err := cmd.Run()
		e, ok := err.(*exec.ExitError)
		require.Equal(t, true, ok, "should be exit error")
		require.Equal(t, false, e.Success())
		require.Equal(t, "exit status 1", e.Error())
		return
	}
	ensurePassword()
}
