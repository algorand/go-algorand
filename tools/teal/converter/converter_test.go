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

package converter

import (
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReadInstructions(t *testing.T) {
	byteCode := []byte{0x03, 0x63}
	p, err := NewProgram(byteCode)
	require.EqualError(t, err, "while parsing opcode 63: EOF")

	text := `
		byte "1234"
		int 1
		int 2
		+
		b label
		byte "abcdef"
	label:
		substring 2 25
		int 3
		store 24`
	code, _ := logic.AssembleStringWithVersion(text, 2)
	want := "[0:[20,03010203] 5:[26,02043132333406616263646566] 19:[28,] 20:[22,] 21:[23,] 22:[8,] 23:[42,0001] 26:[29,] 27:[51,0219] 30:[24,] 31:[35,18]]"
	code.Program[0] = 3
	p, _ = NewProgram(code.Program)
	require.Equal(t, want, p.String())
}

func TestBranchInst_Convert(t *testing.T) {
	tests := []struct {
		name       string
		inst       *Instruction
		addrMap    []int
		wantOffset []byte
		wantErrStr string
	}{
		{
			name:       "zero offset",
			inst:       NewInstruction(0x40, []byte{0x00, 0x00}, 2),
			addrMap:    []int{0, 0, 2, 0, 0, 42, 0, 0},
			wantOffset: []byte{0, 37},
		},
		{
			name:       "normal",
			inst:       NewInstruction(0x40, []byte{0x00, 0x02}, 2),
			addrMap:    []int{0, 0, 4, 0, 0, 42, 0, 10},
			wantOffset: []byte{0, 3},
		},
		{
			name:       "close to overflow",
			inst:       NewInstruction(0x40, []byte{0x00, 0x00}, 0),
			addrMap:    []int{1, 0, 4, 0x7fff + 4, 0, 42, 0, 10},
			wantOffset: []byte{0x7f, 0xff},
		},
		{
			name:       "+overflow",
			inst:       NewInstruction(0x40, []byte{0x00, 0x00}, 0),
			addrMap:    []int{0, 0, 4, 0x7fff + 4, 0, 42, 0, 10},
			wantErrStr: "overflow in branch's offset",
		},
		{
			name:       "-overflow",
			inst:       NewInstruction(0x40, []byte{0x00, 0x02}, 2),
			addrMap:    []int{0, 0, 6, 0, 0, 42, 0, 2},
			wantErrStr: "overflow in branch's offset",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			br := newBranchInst(test.inst)
			addrMap := test.addrMap
			br.SetTranslator(addrMap)
			i, err := br.Convert()
			if test.wantErrStr == "" {
				require.NoError(t, err)
				require.Equal(t, test.wantOffset, i[0].operands)
			} else {
				require.EqualError(t, err, test.wantErrStr)
			}

		})
	}
}

func TestProgram_ConvertTo(t *testing.T) {
	tests := []struct {
		name              string
		byteCode          []byte
		v                 Version
		wantByteCode      []byte
		wantAssembly      string
		wantParsErr       string
		wantConversionErr string
	}{
		{
			byteCode:    []byte{0x03, 0x67},
			wantParsErr: "while parsing opcode 67: EOF",
		},
		{
			byteCode:     []byte{0x03},
			v:            10,
			wantByteCode: []byte{10},
		},
		{
			byteCode:          []byte{0x03, 0x05},
			v:                 1,
			wantConversionErr: "can not convert from version 3 to version 1",
		},
		{
			byteCode:          []byte{0x03, 0x41, 0x0, 0x0},
			wantConversionErr: "trying to branch out of the program",
		},
		{
			name:         "put the version tag",
			byteCode:     []byte{0x03, 0x41, 0x0, 0x0, 0x03},
			wantByteCode: []byte{0x02, 0x41, 0x0, 0x0, 0x03},
		},
		{
			name:         "without br",
			byteCode:     []byte{0x03, 0x63, 0x15, 0x15, 0x66, 0xff, 0x62, 0x0},
			wantAssembly: "// version 2\nbytecblock 0x15\nbytec_0\napp_local_get_ex\nlen\nstore 255\nbytecblock 0xff\nbytec_0\nload 255\napp_local_put\nbytecblock 0x00\nbytec_0\napp_local_get\n",
		},
		{
			name:         "br to changed inst",
			byteCode:     []byte{0x03, 0x40, 0x0, 0x0, 0x65, 0x0},
			wantByteCode: []byte{0x2, 0x40, 0x0, 0x0, 0x26, 0x1, 0x1, 0x0, 0x28, 0x65},
		},
		{
			name:         "br to end",
			byteCode:     []byte{0x03, 0x69, 0xaa, 0x41, 0x0, 0x03, 0x51, 0x20, 0x21, 0x2d},
			wantByteCode: []byte{0x2, 0x26, 0x1, 0x1, 0xaa, 0x28, 0x69, 0x41, 0x0, 0x3, 0x51, 0x20, 0x21, 0x2d},
		},
		{
			name:         "multiple br",
			byteCode:     []byte{0x03, 0x42, 0x0, 0x05, 0x67, 0xfe, 0x40, 0x0, 0x02, 0x68, 0x11, 0x1c},
			wantByteCode: []byte{0x2, 0x42, 0x0, 0xd, 0x35, 0xff, 0x26, 0x1, 0x1, 0xfe, 0x28, 0x34, 0xff, 0x67, 0x40, 0x0, 0x6, 0x26, 0x1, 0x1, 0x11, 0x28, 0x68, 0x1c},
		},
		{
			name:         "disassemble",
			byteCode:     []byte{0x03, 0x62, 0x33, 0x42, 0x0, 0x02, 0x67, 0x77, 0x71, 0x04, 0x36, 0x1, 0x1},
			wantAssembly: "// version 2\nbytecblock 0x33\nbytec_0\napp_local_get\nb label1\nstore 255\nbytecblock 0x77\nbytec_0\nload 255\napp_global_put\nlabel1:\nasset_params_get AssetName\ntxna Fee 1\n",
		},
		{
			name:         "disaasemble br to changed",
			byteCode:     []byte{0x03, 0x4a, 0x41, 0x0, 0x02, 0x62, 0x22, 0x64, 0x33},
			wantAssembly: "// version 2\ndup2\nbz label1\nbytecblock 0x22\nbytec_0\napp_local_get\nlabel1:\nbytecblock 0x33\nbytec_0\napp_global_get\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := NewProgram(test.byteCode)
			if test.wantParsErr != "" {
				require.EqualError(t, err, test.wantParsErr)
				return
			}
			require.NoError(t, err)
			if test.v == 0 {
				test.v = DefaultOldTealVersion
			}
			b, err := p.ConvertTo(test.v)
			if test.wantConversionErr != "" {
				require.EqualError(t, err, test.wantConversionErr)
				return
			}
			require.NoError(t, err)
			if test.wantByteCode != nil {
				require.Equal(t, test.wantByteCode, b)
			} else {
				s, _ := logic.Disassemble(b)
				require.Equal(t, test.wantAssembly, s)
			}
		})
	}
}

func TestNewBranchInst(t *testing.T) {
	br := newBranchInst(NewInstruction(0x40, []byte{0x20, 0x25}, 5))
	want := "5:[40,2025] 8229"
	require.Equal(t, want, br.String())

	br = newBranchInst(NewInstruction(0x40, []byte{0x7f, 0xff}, 5))
	require.Equal(t, 32767, br.offset)
	require.Panics(t, func() { br.Convert() })
}
