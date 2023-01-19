// Copyright (C) 2019-2023 Algorand, Inc.
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
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/routes"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type TestSuite struct {
	suite.Suite
	e *echo.Echo
}

func (s *TestSuite) SetupSuite() {
	s.e = echo.New()
	// Make a deep copy of the routes array with handlers.
	v1RoutesCopy := make([]lib.Route, len(routes.V1Routes))
	for _, route := range routes.V1Routes {
		v1RoutesCopy = append(v1RoutesCopy, lib.Route{
			Name:        route.Name,
			Method:      route.Method,
			Path:        route.Path,
			HandlerFunc: route.HandlerFunc,
		})
	}
	// Make a ReqContext with an initialized logger to prevent nil dereferencing.
	reqCtx := lib.ReqContext{Log: logging.NewLogger()}
	// Registering v1 routes
	registerHandlers(s.e, apiV1Tag, v1RoutesCopy, reqCtx)
}

func (s *TestSuite) TestGetTransactionV1Sunset() {
	testCases := []struct {
		path  string
		route string
	}{
		{"/v1/account/address-param/transactions/pending", "/v1/account/:addr/transactions/pending"},
		{"/v1/status/wait-for-block-after/123456", "/v1/status/wait-for-block-after/:round"},
		{"/v1/block/123456", "/v1/block/:round"},
		{"/v1/transactions/pending/ASPB5E72OT2UWSOCQGD5OPT3W4KV4LZZDL7L5MBCC3EBAIJCDHAA", "/v1/transactions/pending/:txid"},
		{"/v1/asset/123456", "/v1/asset/:index"},
	}

	rec := httptest.NewRecorder()
	ctx := s.e.NewContext(nil, rec)

	for _, testCase := range testCases {
		s.e.Router().Find(http.MethodGet, testCase.path, ctx)
		assert.Equal(s.T(), testCase.route, ctx.Path())

		// Check that router correctly routes to the v1Sunset handler.
		assert.Equal(s.T(), nil, ctx.Handler()(ctx))
		assert.NotNil(s.T(), rec.Body)
		assert.Equal(s.T(), http.StatusGone, rec.Code)
	}

}

func TestTestSuite(t *testing.T) {
	partitiontest.PartitionTest(t)
	suite.Run(t, new(TestSuite))
}
