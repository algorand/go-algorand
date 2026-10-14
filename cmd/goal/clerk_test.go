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

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func abs(t *testing.T, path string) string {
	t.Helper()
	absPath, err := filepath.Abs(path)
	require.NoError(t, err)
	return absPath
}

func TestAuthorizeWithProgram(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	program := []byte{0x06, 0x81, 0x01} // #pragma version 6; int 1
	lsig := transactions.LogicSig{Logic: program, Args: [][]byte{[]byte("arg")}}

	legacyAddr := basics.Address(logic.HashProgram(program))
	saltedSalt, saltedAddr := saltedProgramAuthorizer(program)
	require.NotEqual(t, legacyAddr, saltedAddr)
	require.True(t, saltedAddr.IsPQCompliant())

	// Without the flag, a program authorizes from its hash, as it always has.
	legacy := transactions.SignedTxn{Txn: transactions.Transaction{Header: transactions.Header{Sender: legacyAddr}}}
	authorizeWithProgram(&legacy, lsig, false)
	require.Equal(t, lsig, legacy.Lsig)
	require.True(t, legacy.PQsig.Blank())

	// The flag moves it to the salted form, which carries the args in place of
	// signature bytes.
	salted := transactions.SignedTxn{Txn: transactions.Transaction{Header: transactions.Header{Sender: saltedAddr}}}
	authorizeWithProgram(&salted, lsig, true)
	require.True(t, salted.Lsig.Blank())
	require.Equal(t, protocol.PQSchemeLogicSig, salted.PQsig.Scheme)
	require.Equal(t, saltedSalt, salted.PQsig.Salt)
	require.Equal(t, program, salted.PQsig.PublicKey)
	decoded, err := salted.PQsig.Lsig()
	require.NoError(t, err)
	require.Equal(t, lsig.Args, [][]byte(decoded.Args))

	// A sender that is already the salted address picks that form on its own,
	// so a caller who knows the account need not say which form it uses.
	inferred := transactions.SignedTxn{Txn: transactions.Transaction{Header: transactions.Header{Sender: saltedAddr}}}
	authorizeWithProgram(&inferred, lsig, false)
	require.Equal(t, salted.PQsig, inferred.PQsig)

	// Rekeying names the authorizer somewhere other than the sender, and that is
	// what the form is read from.
	rekeyed := transactions.SignedTxn{
		Txn:      transactions.Transaction{Header: transactions.Header{Sender: basics.Address{1}}},
		AuthAddr: saltedAddr,
	}
	authorizeWithProgram(&rekeyed, lsig, false)
	require.Equal(t, salted.PQsig, rekeyed.PQsig)
}

func TestDeterminePathToSourceFromSourceMap(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		name       string
		sourceFile string
		outFile    string

		expectedPath string
	}{
		{
			name:         "same directory",
			sourceFile:   filepath.FromSlash("data/program.teal"),
			outFile:      filepath.FromSlash("data/program.teal.tok"),
			expectedPath: "program.teal",
		},
		{
			name:         "output one level up",
			sourceFile:   filepath.FromSlash("data/program.teal"),
			outFile:      filepath.FromSlash("data/output/program.teal.tok"),
			expectedPath: filepath.FromSlash("../program.teal"),
		},
		{
			name:         "output one level down",
			sourceFile:   filepath.FromSlash("data/program.teal"),
			outFile:      "program.teal.tok",
			expectedPath: filepath.FromSlash("data/program.teal"),
		},
		{
			name:         "input stdin",
			sourceFile:   stdinFileNameValue,
			outFile:      "program.teal.tok",
			expectedPath: "<stdin>",
		},
		{
			name:         "output stdout",
			sourceFile:   filepath.FromSlash("data/program.teal"),
			outFile:      stdoutFilenameValue,
			expectedPath: abs(t, filepath.FromSlash("data/program.teal")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sources := []string{tc.sourceFile}
			if tc.sourceFile != stdinFileNameValue {
				sources = append(sources, abs(t, tc.sourceFile))
			}
			outs := []string{tc.outFile}
			if tc.outFile != stdoutFilenameValue {
				outs = append(outs, abs(t, tc.outFile))
			}

			for sourceIndex, source := range sources {
				for outIndex, out := range outs {
					actualPath, err := determinePathToSourceFromSourceMap(source, out)
					require.NoError(t, err, "sourceIndex: %d, outIndex: %d", sourceIndex, outIndex)
					require.Equal(t, tc.expectedPath, actualPath, "sourceIndex: %d, outIndex: %d", sourceIndex, outIndex)
				}
			}
		})
	}
}
