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

package network

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestPubsubTracer_TagList makes sure pubsubMetricsTracer traces pubsub messages
// by counting switch cases in SendRPC and ValidateMessage
func TestMetrics_PubsubTracer_TagList(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "metrics.go", nil, 0)
	require.NoError(t, err)

	// Find the SendRPC/ValidateMessage functions and count the switch cases
	var sendCaseCount int
	var recvCaseCount int
	ast.Inspect(f, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.FuncDecl:
			if stmt.Name.Name == "SendRPC" {
				ast.Inspect(stmt.Body, func(n ast.Node) bool {
					if switchStmt, ok := n.(*ast.SwitchStmt); ok {
						for _, stmt := range switchStmt.Body.List {
							if _, ok := stmt.(*ast.CaseClause); ok {
								sendCaseCount++
							}
						}
					}
					return true
				})
			}
			if stmt.Name.Name == "RecvRPC" {
				ast.Inspect(stmt.Body, func(n ast.Node) bool {
					if switchStmt, ok := n.(*ast.SwitchStmt); ok {
						for _, stmt := range switchStmt.Body.List {
							if _, ok := stmt.(*ast.CaseClause); ok {
								recvCaseCount++
							}
						}
					}
					return true
				})
			}
		}
		return true
	})

	require.Equal(t, len(gossipSubTags), sendCaseCount)
	require.Equal(t, len(gossipSubTags), recvCaseCount)
}
