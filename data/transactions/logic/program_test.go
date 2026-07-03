// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package logic

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPQDelegatedProgramToBeHashed(t *testing.T) {
	partitiontest.PartitionTest(t)

	pqAddress := basics.Address{1, 2, 3}
	program := []byte{4, 5, 6}

	hashID, bytes := (PQDelegatedProgram{Addr: pqAddress, Program: program}).ToBeHashed()
	require.Equal(t, protocol.PostQuantumDelegatedProgram, hashID)
	require.Equal(t, protocol.HashID("PQProgram"), hashID)
	require.NotEqual(t, protocol.Program, hashID)
	require.NotEqual(t, protocol.MultisigProgram, hashID)
	require.Equal(t, append(pqAddress[:], program...), bytes)
}

func TestPQDelegatedProgramBindsAddressAndProgram(t *testing.T) {
	partitiontest.PartitionTest(t)

	pqAddress := basics.Address{1}
	program := []byte{2}
	_, base := (PQDelegatedProgram{Addr: pqAddress, Program: program}).ToBeHashed()

	pqAddress[0] = 3
	_, changedPQAddress := (PQDelegatedProgram{Addr: pqAddress, Program: program}).ToBeHashed()
	require.NotEqual(t, base, changedPQAddress)

	pqAddress[0] = 1
	program[0] = 4
	_, changedProgram := (PQDelegatedProgram{Addr: pqAddress, Program: program}).ToBeHashed()
	require.NotEqual(t, base, changedProgram)
}
