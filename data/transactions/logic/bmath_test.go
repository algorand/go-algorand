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
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/stretchr/testify/require"
	"testing"
)

const bmathCompiled = "800301234549a0a049a0a149a0a249a0a349a0a4a0af49a0a5a0af49a0a6a0af49a0a7a0af49a0a8a0af49a0a9a0af49a0aa49a0ab49a0ac49a0ada0ae"

const bmathNonsense = `
 pushbytes 0x012345
 dup
 b+
 dup
 b-
 dup
 b/
 dup
 b*
 dup
 b<
 bzero
 dup
 b>
 bzero
 dup
 b<=
 bzero
 dup
 b>=
 bzero
 dup
 b==
 bzero
 dup
 b!=
 bzero
 dup
 b%
 dup
 b|
 dup
 b&
 dup
 b^
 b~
`

func TestDeprecation(t *testing.T) {
	var txn transactions.SignedTxn
	txn.Lsig.Logic = []byte{byte(multiVersion), 0x80, 0x01, 0x01, 0x49, 0xa2}
	ep := defaultEvalParamsWithVersion(&txn, multiVersion)
	_, err := EvalSignature(0, ep)
	require.ErrorContains(t, err, "deprecated opcode")
}
