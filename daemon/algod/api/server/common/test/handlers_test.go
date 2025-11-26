// Copyright (C) 2019-2025 Algorand, Inc.
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

package test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/common"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func mockNodeStatusInRangeHelper(
	t *testing.T, statusCode MockNodeCatchupStatus,
	expectedErr string, expectedStatus node.StatusReport) {
	mockNodeInstance := makeMockNode(statusCode)
	status, err := mockNodeInstance.Status()
	if expectedErr != "" {
		require.EqualError(t, err, expectedErr)
	} else {
		require.Equal(t, expectedStatus, status)
	}
}

func TestMockNodeStatus(t *testing.T) {
	partitiontest.PartitionTest(t)

	mockNodeStatusInRangeHelper(
		t, CaughtUpAndReady, "", cannedStatusReportCaughtUpAndReadyGolden)
	mockNodeStatusInRangeHelper(
		t, CatchingUpFast, "", cannedStatusReportCatchingUpFastGolden)
	mockNodeStatusInRangeHelper(
		t, StoppedAtUnsupported, "", cannedStatusReportStoppedAtUnsupportedGolden)
	mockNodeStatusInRangeHelper(
		t, 399, "catchup status out of scope error", node.StatusReport{})
}

func readyEndpointTestHelper(
	t *testing.T, node *mockNode, expectedCode int) {
	reqCtx := lib.ReqContext{
		Node:     node,
		Log:      logging.NewLogger(),
		Shutdown: make(chan struct{}),
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	common.Ready(reqCtx, c)
	require.Equal(t, expectedCode, rec.Code)
}

func TestReadyEndpoint(t *testing.T) {
	partitiontest.PartitionTest(t)

	mockNodeInstance := makeMockNode(CaughtUpAndReady)
	readyEndpointTestHelper(t, mockNodeInstance, http.StatusOK)

	mockNodeInstance.catchupStatus = CatchingUpFast
	readyEndpointTestHelper(t, mockNodeInstance, http.StatusServiceUnavailable)

	mockNodeInstance.catchupStatus = StoppedAtUnsupported
	readyEndpointTestHelper(t, mockNodeInstance, http.StatusInternalServerError)
}
