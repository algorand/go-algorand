// Copyright (C) 2019-2022 Algorand, Inc.
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
	"fmt"
	"reflect"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestOpSpecs(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	for _, spec := range OpSpecs {
		require.NotEmpty(t, spec.OpDetails, spec)
	}
}

func (os *OpSpec) equals(oso *OpSpec) bool {
	if os.Opcode != oso.Opcode {
		return false
	}
	if os.Name != oso.Name {
		return false
	}
	if !reflect.DeepEqual(os.Arg, oso.Arg) {
		return false
	}
	if !reflect.DeepEqual(os.Return, oso.Return) {
		return false
	}
	if os.Version != oso.Version {
		return false
	}
	if os.Modes != oso.Modes {
		return false
	}

	return true
}

func TestOpcodesByVersionReordered(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Make a copy to restore to the original
	OpSpecsOrig := make([]OpSpec, len(OpSpecs))
	for idx, opspec := range OpSpecs {
		cp := opspec
		OpSpecsOrig[idx] = cp
	}
	defer func() {
		OpSpecs = OpSpecsOrig
	}()

	// To test the case where a newer version opcode is before an older version
	// Change the order of opcode 0x01 so that version 2 comes before version 1
	tmp := OpSpecs[1]
	OpSpecs[1] = OpSpecs[4]
	OpSpecs[4] = tmp

	t.Run("TestOpcodesByVersion", testOpcodesByVersion)
}

func TestOpcodesByVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	testOpcodesByVersion(t)
}

func testOpcodesByVersion(t *testing.T) {
	// Make a copy of the OpSpecs to check if OpcodesByVersion will change it
	OpSpecs2 := make([]OpSpec, len(OpSpecs))
	for idx, opspec := range OpSpecs {
		cp := opspec
		OpSpecs2[idx] = cp
	}

	opSpecs := make([][]OpSpec, LogicVersion)
	for v := uint64(1); v <= LogicVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			opSpecs[v-1] = OpcodesByVersion(v)
			isOk := true
			for i := 0; i < len(opSpecs[v-1])-1; i++ {
				cur := opSpecs[v-1][i]
				next := opSpecs[v-1][i+1]
				// check duplicates
				if cur.Opcode == next.Opcode {
					isOk = false
					break
				}
				// check sorted
				if cur.Opcode > next.Opcode {
					isOk = false
					break
				}

			}
			require.True(t, isOk)
		})
	}
	require.Greater(t, len(opSpecs[1]), len(opSpecs[0]))

	for idx, opspec := range OpSpecs {
		require.True(t, opspec.equals(&OpSpecs2[idx]))
	}
}

func TestOpcodesVersioningV2(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	require.Equal(t, LogicVersion+1, len(opsByOpcode))
	require.Equal(t, LogicVersion+1, len(OpsByName))

	// ensure v0 has only v0 opcodes
	cntv0 := 0
	for _, spec := range opsByOpcode[0] {
		if spec.op != nil {
			require.Equal(t, uint64(0), spec.Version)
			cntv0++
		}
	}
	for _, spec := range OpsByName[0] {
		if spec.op != nil {
			require.Equal(t, uint64(0), spec.Version)
		}
	}
	require.Equal(t, cntv0, len(OpsByName[0]))

	// ensure v1 has only v1 opcodes
	cntv1 := 0
	for _, spec := range opsByOpcode[1] {
		if spec.op != nil {
			require.Equal(t, uint64(1), spec.Version, spec)
			cntv1++
		}
	}
	for _, spec := range OpsByName[1] {
		if spec.op != nil {
			require.Equal(t, uint64(1), spec.Version)
		}
	}
	require.Equal(t, cntv1, len(OpsByName[1]))
	require.Equal(t, cntv1, cntv0)
	require.Equal(t, 52, cntv1)

	eqButVersion := func(a *OpSpec, b *OpSpec) (eq bool) {
		eq = a.Opcode == b.Opcode && a.Name == b.Name &&
			reflect.ValueOf(a.op).Pointer() == reflect.ValueOf(b.op).Pointer() &&
			reflect.ValueOf(a.asm).Pointer() == reflect.ValueOf(b.asm).Pointer() &&
			reflect.DeepEqual(a.Arg, b.Arg) && reflect.DeepEqual(a.Return, b.Return) &&
			a.Modes == b.Modes &&
			a.OpDetails.FullCost == b.OpDetails.FullCost && a.OpDetails.Size == b.OpDetails.Size &&
			reflect.ValueOf(a.OpDetails.check).Pointer() == reflect.ValueOf(b.OpDetails.check).Pointer()
		return
	}
	// ensure v0 and v1 are the same
	require.Equal(t, len(opsByOpcode[1]), len(opsByOpcode[0]))
	require.Equal(t, len(OpsByName[1]), len(OpsByName[0]))
	for op, spec1 := range opsByOpcode[1] {
		spec0 := opsByOpcode[0][op]
		msg := fmt.Sprintf("%v\n%v\n", spec0, spec1)
		require.True(t, eqButVersion(&spec1, &spec0), msg)
	}
	for name, spec1 := range OpsByName[1] {
		spec0 := OpsByName[0][name]
		require.True(t, eqButVersion(&spec1, &spec0))
	}

	// ensure v2 has v1 and v2 opcodes
	cntv2 := 0
	cntAdded := 0
	for _, spec := range opsByOpcode[2] {
		if spec.op != nil {
			require.True(t, spec.Version == 1 || spec.Version == 2)
			if spec.Version == 2 {
				cntAdded++
			}
			cntv2++
		}
	}
	for _, spec := range OpsByName[2] {
		if spec.op != nil {
			require.True(t, spec.Version == 1 || spec.Version == 2)
		}
	}
	require.Equal(t, cntv2, len(OpsByName[2]))

	// hardcode and ensure amount of new v2 opcodes
	newOpcodes := 22
	overwritten := 3 // sha256, keccak256, sha512_256
	require.Equal(t, newOpcodes+overwritten, cntAdded)

	require.Equal(t, cntv2, cntv1+newOpcodes)

	// ensure v3 has v1, v2, v3 opcodes
	cntv3 := 0
	cntAdded = 0
	for _, spec := range opsByOpcode[3] {
		if spec.op != nil {
			require.True(t, spec.Version == 1 || spec.Version == 2 || spec.Version == 3)
			if spec.Version == 3 {
				cntAdded++
			}
			cntv3++
		}
	}
	for _, spec := range OpsByName[3] {
		if spec.op != nil {
			require.True(t, spec.Version == 1 || spec.Version == 2 || spec.Version == 3)
		}
	}
	require.Len(t, OpsByName[3], cntv3)

	// assert, min_balance, {get,set}{bit,byte}, swap, select, dig, stxn, stxna, push{int,bytes}
	newOpcodes = 13
	overwritten = 0 // ? none yet
	require.Equal(t, newOpcodes+overwritten, cntAdded)

}
