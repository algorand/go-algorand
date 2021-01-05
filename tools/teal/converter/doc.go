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

/*
Package converter implements a converter for converting array-style memory manipulation instructions to key-value
instructions which TEALv2 uses. These array-style memory instructions have the following description:

app_local_get
	Opcode: 0x62 {uint8[0..0xFE] i: position in local memory segment}
	Pops: ... stack, {uint64 A}
	Pushes: any
	read from account specified by Txn.Accounts[A] from local memory segment of the current application at position 'i' => value
	LogicSigVersion >= 3
	Mode: Application
	params: account index. Return: value. The value is zero if the key or index does not exist.

'i' must be an index between [0, 0xFE] (inclusive)
Note for version 3: this opcode clears bytes constants block

OpcodeConversionType: MemoryAccess

Converts to:
	byte []byte{i}
	app_local_get
------------------------------

app_local_get_ex
	Opcode: 0x63 {uint8[0..0xFE] i: position in local memory segment}
	Pops: ... stack, {uint64 A}, {uint64 B}
	Pushes: uint64, any
	read from account specified by Txn.Accounts[A] from local memory segment of the application B at position 'i' => {0 or 1 (top), value}
	LogicSigVersion >= 3
	Mode: Application
	params: account index, application id. Return: did_exist flag (top of the stack, 1 if exist and 0 otherwise), value.

'i' must be an index between [0, 0xFE] (inclusive)
Note for version 3: this opcode clears bytes constants block

OpcodeConversionType: MemoryAccess

Converts to:
	byte []byte{i}
	app_local_get_ex
------------------------------

app_global_get
	Opcode: 0x64 {uint8[0..0xFE] i: position in global memory segment}
	Pops: None
	Pushes: any
	read from global memory segment of a current application at position 'i' => value
	LogicSigVersion >= 3
	Mode: Application
	params: none. Return: value. The value is zero if the index does not exist.

'i' must be an index between [0, 0xFE] (inclusive)
Note for version 3: this opcode clears bytes constants block

OpcodeConversionType: MemoryAccess

Converts to:
	byte []byte{i}
	app_global_get
------------------------------

app_global_get_ex
	Opcode: 0x65 {uint8[0..0xFE] i: position in global memory segment}
	Pops: ... stack, {uint64 A}
	Pushes: uint64, any
	read from application Txn.ForeignApps[A] global memory segment at position 'i' => {0 or 1 (top), value}. A is specified as an account index in the ForeignApps field of the ApplicationCall transaction, zero index means this app
	LogicSigVersion >= 3
	Mode: Application
	params: application index, state key. Return: did_exist flag (top of the stack, 1 if exist and 0 otherwise), value.

'i' must be an index between [0, 0xFE] (inclusive)
Note for version 3: this opcode clears bytes constants block

OpcodeConversionType: MemoryAccess

Converts to:
	byte []byte{i}
	app_global_get_ex
------------------------------

app_local_put
	Opcode: 0x66 {uint8[0..0xFE] i: position in local memory segment}
	Pops: ... stack, {uint64 A}, {any C}
	Pushes: None
	write to account specified by Txn.Accounts[A] to local memory segment of a current application at position 'i' with value C
	LogicSigVersion >= 3
	Mode: Application
	params: account index, value.

'i' must be an index between [0, 0xFE] (inclusive)
Note for version 3: this opcode clears position 0xFF of scratch space and bytes constants block

OpcodeConversionType: MemoryWrite

Converts To:
	store 255
	byte []byte{i}
	load 255
	app_local_put
------------------------------

app_global_put
	Opcode: 0x67 {uint8[0..0xFE] i: position in global memory segment}
	Pops: ... stack, {any B}
	Pushes: None
	write value B to global memory segment of the current application at position 'i'
	LogicSigVersion >= 3
	Mode: Application

'i' must be an index between [0, 0xFE] (inclusive)
Note for version 3: this opcode clears position 0xFF of scratch space and bytes constants block

OpcodeConversionType: MemoryWrite

Converts to:
	store 255
	byte []byte{i}
	load 255
	app_global_put
------------------------------

app_local_del
	Opcode: 0x68 {uint8[0..0xFE] i: position in local memory segment}
	Pops: ... stack, {uint64 A}
	Pushes: None
	delete from account specified by Txn.Accounts[A] local memory segment of the current application at position 'i'
	LogicSigVersion >= 3
	Mode: Application
	params: account index

'i' must be an index between [0, 0xFE] (inclusive)
Deleting an index which is already absent has no effect on the application local state. (In particular, it does not cause the program to fail.)
Note for version 3: this opcode clears position 0xFF of scratch space and bytes constants block

OpcodeConversionType: MemoryAccess

Converts to:
	byte []byte{i}
	app_local_del
------------------------------

app_global_del
	Opcode: 0x69 {uint8[0..0xFE] i: position in global memory segment}
	Pops: None
	Pushes: None
	delete position 'i' from a global state of the current application
	LogicSigVersion >= 3
	Mode: Application

'i' must be an index between [0, 0xFE] (inclusive)
Deleting an index which is already absent has no effect on the application global state. (In particular, it does not cause the program to fail.)
Note for version 3: this opcode clears bytes constants block

OpcodeConversionType: MemoryAccess

Converts to:
	byte []byte{i}
	app_global_del
------------------------------

Instructions of type MemoryAccess will be converted to the following byte-code:
	[0x26 0x01 0x01 {i} 0x28 opcode]

Instructions of type MemoryWrite will be converted to the following byte-code:
	[0x35 0xFF 0x26 0x01 0x01 {i} 0x28 0x34 0xFF opcode]

Besides these instructions converter updates offset of Branch instructions to make sure that all branches in the
converted code branch to the same instruction as in the original code.
*/
package converter
