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

package simulation

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// ==============================
// > Test Helpers
// ==============================

// ==============================
// > Simulation Tests
// ==============================

// > Simulate Without Debugger

func TestCursorDebuggerHooks(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type Hook int64

	const (
		BeforeTxn Hook = iota
		AfterTxn
		BeforeInnerTxnGroup
		AfterInnerTxnGroup
	)

	type step struct {
		action       Hook
		expectedPath TxnPath
	}

	type testCase struct {
		name              string
		timeline          []step
		expectedPathAtEnd TxnPath
	}

	testCases := []testCase{
		{
			name:              "empty",
			timeline:          []step{},
			expectedPathAtEnd: TxnPath{},
		},
		{
			name: "single txn",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: AfterTxn, expectedPath: TxnPath{0}},
			},
		},
		{
			name: "two txns",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: AfterTxn, expectedPath: TxnPath{0}},
				{action: BeforeTxn, expectedPath: TxnPath{1}},
				{action: AfterTxn, expectedPath: TxnPath{1}},
			},
		},
		{
			name: "many txns",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: AfterTxn, expectedPath: TxnPath{0}},
				{action: BeforeTxn, expectedPath: TxnPath{1}},
				{action: AfterTxn, expectedPath: TxnPath{1}},
				{action: BeforeTxn, expectedPath: TxnPath{2}},
				{action: AfterTxn, expectedPath: TxnPath{2}},
				{action: BeforeTxn, expectedPath: TxnPath{3}},
				{action: AfterTxn, expectedPath: TxnPath{3}},
				{action: BeforeTxn, expectedPath: TxnPath{4}},
				{action: AfterTxn, expectedPath: TxnPath{4}},
			},
		},
		{
			name: "single txn with inner txn",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0}},
			},
		},
		{
			name: "single txn with multiple serial inner txns",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterInnerTxnGroup},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 1}},
				{action: AfterTxn, expectedPath: TxnPath{0, 1}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0}},
			},
		},
		{
			name: "single txn with 2 serial inner txns with another inner txn in the second one",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterInnerTxnGroup},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 1}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 1, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 1, 0}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0, 1}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0}},
			},
		},
		{
			name: "single txn with 2 serial inner txns with 2 serial inner txns in the second one",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterInnerTxnGroup},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 1}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 1, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 1, 0}},
				{action: AfterInnerTxnGroup},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 1, 1}},
				{action: AfterTxn, expectedPath: TxnPath{0, 1, 1}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0, 1}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0}},
			},
		},
		{
			name: "single txn with 2 serial inner txns with an inner txn in the first one and 2 serial inner txns in the second one",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 0}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 0, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 0, 0}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0, 0}},
				{action: AfterInnerTxnGroup},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 1}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 1, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 1, 0}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0, 1}},
				{action: BeforeTxn, expectedPath: TxnPath{0, 2}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{0, 2, 0}},
				{action: AfterTxn, expectedPath: TxnPath{0, 2, 0}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0, 2}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{0}},
			},
		},
		{
			name: "second txn with deep inners",
			timeline: []step{
				{action: BeforeTxn, expectedPath: TxnPath{0}},
				{action: AfterTxn, expectedPath: TxnPath{0}},
				{action: BeforeTxn, expectedPath: TxnPath{1}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{1, 0}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{1, 0, 0}},
				{action: BeforeInnerTxnGroup},
				{action: BeforeTxn, expectedPath: TxnPath{1, 0, 0, 0}},
				{action: AfterTxn, expectedPath: TxnPath{1, 0, 0, 0}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{1, 0, 0}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{1, 0}},
				{action: AfterInnerTxnGroup},
				{action: AfterTxn, expectedPath: TxnPath{1}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s", tc.name), func(t *testing.T) {
			cursor := TxnPath{}
			hook := cursorDebuggerHook{
				cursor: cursor,
			}

			// These don't matter so they can be nil
			ep := logic.EvalParams{}
			groupIndex := 0

			for _, step := range tc.timeline {
				switch step.action {
				case BeforeTxn:
					hook.BeforeTxn(&ep, groupIndex)
				case AfterTxn:
					hook.AfterTxn(&ep, groupIndex)
				case BeforeInnerTxnGroup:
					hook.BeforeInnerTxnGroup(&ep)
				case AfterInnerTxnGroup:
					hook.AfterInnerTxnGroup(&ep)
				default:
					t.Fatalf("unexpected timeline hook: %d", step.action)
				}
				if step.expectedPath != nil {
					switch step.action {
					case BeforeInnerTxnGroup, AfterInnerTxnGroup:
						t.Fatalf("Path is unspecified for hook: %d", step.action)
					}
					require.Equal(t, step.expectedPath, hook.cursor)
				}
			}

			if tc.expectedPathAtEnd != nil {
				require.Equal(t, tc.expectedPathAtEnd, hook.cursor)
			}
		})
	}
}
