// Copyright (C) 2019-2024 Algorand, Inc.
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
	"testing"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestCursorEvalTracer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type step struct {
		action       mocktracer.EventType
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
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
		{
			name: "two txns",
			timeline: []step{
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{1}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{1}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
		{
			name: "many txns",
			timeline: []step{
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{1}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{1}},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{2}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{2}},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{3}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{3}},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{4}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{4}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
		{
			name: "single txn with inner txn",
			timeline: []step{
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
		{
			name: "single txn with multiple serial inner txns",
			timeline: []step{
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 1}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 1}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
		{
			name: "single txn with 2 serial inner txns with another inner txn in the second one",
			timeline: []step{
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 1}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 1, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 1, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 1}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
		{
			name: "single txn with 2 serial inner txns with 2 serial inner txns in the second one",
			timeline: []step{
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 1}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 1, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 1, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 1, 1}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 1, 1}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 1}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
		{
			name: "single txn with 2 serial inner txns with an inner txn in the first one and 2 serial inner txns in the second one",
			timeline: []step{
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 0, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 0, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 1}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 1, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 1, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 1}},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 2}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0, 2, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 2, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0, 2}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
		{
			name: "second txn with deep inners",
			timeline: []step{
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{0}},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{1}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{1, 0}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{1, 0, 0}},
				{action: mocktracer.BeforeTxnGroupEvent},
				{action: mocktracer.BeforeTxnEvent, expectedPath: TxnPath{1, 0, 0, 0}},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{1, 0, 0, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{1, 0, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{1, 0}},
				{action: mocktracer.AfterTxnGroupEvent},
				{action: mocktracer.AfterTxnEvent, expectedPath: TxnPath{1}},
				{action: mocktracer.AfterTxnGroupEvent},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var tracer cursorEvalTracer

			// These don't matter so they can be anything
			ep := logic.EvalParams{}
			groupIndex := 0

			for i, step := range tc.timeline {
				switch step.action {
				case mocktracer.BeforeTxnEvent:
					tracer.BeforeTxn(&ep, groupIndex)
				case mocktracer.AfterTxnEvent:
					tracer.AfterTxn(&ep, groupIndex, transactions.ApplyData{}, nil)
				case mocktracer.BeforeTxnGroupEvent:
					tracer.BeforeTxnGroup(&ep)
				case mocktracer.AfterTxnGroupEvent:
					tracer.AfterTxnGroup(&ep, nil, nil)
				default:
					t.Fatalf("unexpected timeline hook: %v", step.action)
				}
				if step.expectedPath != nil {
					switch step.action {
					case mocktracer.BeforeTxnGroupEvent, mocktracer.AfterTxnGroupEvent:
						t.Fatalf("Path is unspecified for hook: %v", step.action)
					}
					require.Equalf(t, step.expectedPath, tracer.absolutePath(), "step index %d (action %v), tracer: %#v", i, step.action, tracer)
				}
			}

			if tc.expectedPathAtEnd != nil {
				require.Equal(t, tc.expectedPathAtEnd, tracer.absolutePath())
			}
		})
	}
}
