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

/*
   app_local_get
       Opcode: 0x62 {uint8[0..0xFE] i: position in local memory segment}
       Pops: ... stack, {uint64 A}
       Pushes: any
       read from account specified by Txn.Accounts[A] from local memory segment of the current application at position 'i' => value
       LogicSigVersion >= 3
       Mode: Application
   'i' must be an index between [0, 0xFE] (inclusive)
   params: account index. Return: value. The value is zero if the key or index does not exist.

   app_local_get_ex
       Opcode: 0x63 {uint8[0..0xFE] i: position in local memory segment}
       Pops: ... stack, {uint64 A}, {uint64 B}
       Pushes: uint64, any
       read from account specified by Txn.Accounts[A] from local memory segment of the application B at position 'i' => {0 or 1 (top), value}
       LogicSigVersion >= 3
       Mode: Application
   'i' must be an index between [0, 0xFE] (inclusive)
   params: account index, application id. Return: did_exist flag (top of the stack, 1 if exist and 0 otherwise), value.

   app_global_get
       Opcode: 0x64 {uint8[0..0xFE] i: position in global memory segment}
       Pops: None
       Pushes: any
       read from global memory segment of a current application at position 'i' => value
       LogicSigVersion >= 3
       Mode: Application
   'i' must be an index between [0, 0xFE] (inclusive)
   params: none. Return: value. The value is zero if the index does not exist.

   app_global_get_ex
       Opcode: 0x65 {uint8[0..0xFE] i: position in global memory segment}
       Pops: ... stack, {uint64 A}
       Pushes: uint64, any
       read from application Txn.ForeignApps[A] global memory segment at position 'i' => {0 or 1 (top), value}. A is specified as an account index in the ForeignApps field of the ApplicationCall transaction, zero index means this app
       LogicSigVersion >= 3
       Mode: Application
   'i' must be an index between [0, 0xFE] (inclusive)
   params: application index, state key. Return: did_exist flag (top of the stack, 1 if exist and 0 otherwise), value.

   app_local_put
       Opcode: 0x66 {uint8[0..0xFE] i: position in local memory segment}
       Pops: ... stack, {uint64 A}, {[]byte B}, {any C}
       Pushes: None
       write to account specified by Txn.Accounts[A] to local memory segment of a current application key B at position 'i' with value C
       LogicSigVersion >= 3
       Mode: Application
   'i' must be an index between [0, 0xFE] (inclusive)
   params: account index, value.

   app_global_put
       Opcode: 0x67 {uint8[0..0xFE] i: position in global memory segment}
       Pops: ... stack, {any B}
       Pushes: None
       write value B to global memory segment of the current application at position 'i'
       LogicSigVersion >= 3
       Mode: Application
   'i' must be an index between [0, 0xFE] (inclusive)

   app_local_del
       Opcode: 0x68 {uint8[0..0xFE] i: position in local memory segment}
       Pops: ... stack, {uint64 A}
       Pushes: None
       delete from account specified by Txn.Accounts[A] local memory segment of the current application at position 'i'
       LogicSigVersion >= 3
       Mode: Application
   'i' must be an index between [0, 0xFE] (inclusive)
   params: account index
   Deleting an index which is already absent has no effect on the application local state. (In particular, it does not cause the program to fail.)

   app_global_del {uint8[0..0xFE] i: position in global memory segment}
       Opcode: 0x69
       Pops: None
       Pushes: None
       delete position 'i' from a global state of the current application
       LogicSigVersion >= 3
       Mode: Application
   'i' must be an index between [0, 0xFE] (inclusive)
   Deleting an index which is already absent has no effect on the application global state. (In particular, it does not cause the program to fail.)
*/
package converter
