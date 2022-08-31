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

	type testCase struct {
		name           string
		timeline       []Hook
		expectedCursor TxnPath
	}

	testCases := []testCase{
		{
			name:           "empty",
			timeline:       []Hook{},
			expectedCursor: TxnPath{},
		},
		{
			name: "single txn",
			timeline: []Hook{
				BeforeTxn,
			},
			expectedCursor: TxnPath{0},
		},
		{
			name: "single txn with inner txn",
			timeline: []Hook{
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
			},
			expectedCursor: TxnPath{0, 0},
		},
		{
			name: "single txn with multiple serial inner txns",
			timeline: []Hook{
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
				AfterTxn,
				AfterInnerTxnGroup,
				BeforeInnerTxnGroup,
				BeforeTxn,
			},
			expectedCursor: TxnPath{0, 1},
		},
		{
			name: "single txn with 2 serial inner txns with another inner txn in the second one",
			timeline: []Hook{
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
				AfterTxn,
				AfterInnerTxnGroup,
				BeforeInnerTxnGroup,
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
			},
			expectedCursor: TxnPath{0, 1, 0},
		},
		{
			name: "single txn with 2 serial inner txns with 2 serial inner txns in the second one",
			timeline: []Hook{
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
				AfterTxn,
				AfterInnerTxnGroup,
				BeforeInnerTxnGroup,
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
				AfterTxn,
				AfterInnerTxnGroup,
				BeforeInnerTxnGroup,
				BeforeTxn,
			},
			expectedCursor: TxnPath{0, 1, 1},
		},
		{
			name: "single txn with 2 serial inner txns with an inner txn in the first one and 2 serial inner txns in the second one",
			timeline: []Hook{
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
				AfterTxn,
				AfterInnerTxnGroup,
				AfterTxn,
				AfterInnerTxnGroup,
				BeforeInnerTxnGroup,
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
				AfterTxn,
				AfterInnerTxnGroup,
				AfterTxn,
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeTxn,
			},
			expectedCursor: TxnPath{0, 2, 0},
		},
		{
			name: "cursor is empty at the end of the timeline",
			timeline: []Hook{
				BeforeTxn,
				BeforeInnerTxnGroup,
				BeforeInnerTxnGroup,
				BeforeInnerTxnGroup,
				AfterInnerTxnGroup,
				AfterInnerTxnGroup,
				AfterInnerTxnGroup,
				AfterTxn,
			},
			expectedCursor: TxnPath{},
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

			for _, h := range tc.timeline {
				switch h {
				case BeforeTxn:
					hook.BeforeTxn(&ep, groupIndex)
				case AfterTxn:
					hook.AfterTxn(&ep, groupIndex)
				case BeforeInnerTxnGroup:
				case AfterInnerTxnGroup:
				default:
					t.Fatalf("unexpected timeline hook: %d", h)
				}
			}

			require.Equal(t, tc.expectedCursor, hook.cursor)
		})
	}
}
