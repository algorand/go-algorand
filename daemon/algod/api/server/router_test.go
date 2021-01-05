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
package server

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/routes"
)

type TestSuite struct {
	suite.Suite
	calls int
	e     *echo.Echo
}

func (s *TestSuite) SetupSuite() {
	s.e = echo.New()
	handler := func(context lib.ReqContext, context2 echo.Context) {
		s.calls++
	}
	// Make a deep copy of the routes array with dummy handlers that log a call.
	v1RoutesCopy := make([]lib.Route, len(routes.V1Routes))
	for _, route := range routes.V1Routes {
		v1RoutesCopy = append(v1RoutesCopy, lib.Route{
			Name:        route.Name,
			Method:      route.Method,
			Path:        route.Path,
			HandlerFunc: handler,
		})
	}
	// Registering v1 routes
	registerHandlers(s.e, apiV1Tag, v1RoutesCopy, lib.ReqContext{})
}
func (s *TestSuite) SetupTest() {
	s.calls = 0
}
func (s *TestSuite) TestBaselineRoute() {
	ctx := s.e.NewContext(nil, nil)
	s.e.Router().Find(http.MethodGet, "/v0/this/is/no/endpoint", ctx)
	assert.Equal(s.T(), echo.ErrNotFound, ctx.Handler()(ctx))
	assert.Equal(s.T(), 0, s.calls)
}
func (s *TestSuite) TestAccountPendingTransaction() {
	ctx := s.e.NewContext(nil, nil)
	s.e.Router().Find(http.MethodGet, "/v1/account/address-param/transactions/pending", ctx)
	assert.Equal(s.T(), "/v1/account/:addr/transactions/pending", ctx.Path())
	assert.Equal(s.T(), "address-param", ctx.Param("addr"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestWaitAfterBlock() {
	ctx := s.e.NewContext(nil, nil)
	s.e.Router().Find(http.MethodGet, "/v1/status/wait-for-block-after/123456", ctx)
	assert.Equal(s.T(), "/v1/status/wait-for-block-after/:round", ctx.Path())
	assert.Equal(s.T(), "123456", ctx.Param("round"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestAccountInformation() {
	ctx := s.e.NewContext(nil, nil)
	s.e.Router().Find(http.MethodGet, "/v1/account/ZBBRQD73JH5KZ7XRED6GALJYJUXOMBBP3X2Z2XFA4LATV3MUJKKMKG7SHA", ctx)
	assert.Equal(s.T(), "/v1/account/:addr", ctx.Path())
	assert.Equal(s.T(), "ZBBRQD73JH5KZ7XRED6GALJYJUXOMBBP3X2Z2XFA4LATV3MUJKKMKG7SHA", ctx.Param("addr"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestTransactionInformation() {
	ctx := s.e.NewContext(nil, nil)
	addr := "ZBBRQD73JH5KZ7XRED6GALJYJUXOMBBP3X2Z2XFA4LATV3MUJKKMKG7SHA"
	txid := "ASPB5E72OT2UWSOCQGD5OPT3W4KV4LZZDL7L5MBCC3EBAIJCDHAA"
	s.e.Router().Find(http.MethodGet, "/v1/account/"+addr+"/transaction/"+txid, ctx)
	assert.Equal(s.T(), "/v1/account/:addr/transaction/:txid", ctx.Path())
	assert.Equal(s.T(), addr, ctx.Param("addr"))
	assert.Equal(s.T(), txid, ctx.Param("txid"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestAccountTransaction() {
	ctx := s.e.NewContext(nil, nil)
	addr := "ZBBRQD73JH5KZ7XRED6GALJYJUXOMBBP3X2Z2XFA4LATV3MUJKKMKG7SHA"
	s.e.Router().Find(http.MethodGet, "/v1/account/"+addr+"/transactions", ctx)
	assert.Equal(s.T(), "/v1/account/:addr/transactions", ctx.Path())
	assert.Equal(s.T(), addr, ctx.Param("addr"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestBlock() {
	ctx := s.e.NewContext(nil, nil)
	s.e.Router().Find(http.MethodGet, "/v1/block/123456", ctx)
	assert.Equal(s.T(), "/v1/block/:round", ctx.Path())
	assert.Equal(s.T(), "123456", ctx.Param("round"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestPendingTransactionID() {
	ctx := s.e.NewContext(nil, nil)
	txid := "ASPB5E72OT2UWSOCQGD5OPT3W4KV4LZZDL7L5MBCC3EBAIJCDHAA"
	s.e.Router().Find(http.MethodGet, "/v1/transactions/pending/"+txid, ctx)
	assert.Equal(s.T(), "/v1/transactions/pending/:txid", ctx.Path())
	assert.Equal(s.T(), txid, ctx.Param("txid"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestPendingTransactionInformationByAddress() {
	ctx := s.e.NewContext(nil, nil)
	addr := "ZBBRQD73JH5KZ7XRED6GALJYJUXOMBBP3X2Z2XFA4LATV3MUJKKMKG7SHA"
	s.e.Router().Find(http.MethodGet, "/v1/account/"+addr+"/transactions/pending", ctx)
	assert.Equal(s.T(), "/v1/account/:addr/transactions/pending", ctx.Path())
	assert.Equal(s.T(), addr, ctx.Param("addr"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestGetAsset() {
	ctx := s.e.NewContext(nil, nil)
	s.e.Router().Find(http.MethodGet, "/v1/asset/123456", ctx)
	assert.Equal(s.T(), "/v1/asset/:index", ctx.Path())
	assert.Equal(s.T(), "123456", ctx.Param("index"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func (s *TestSuite) TestGetTransactionByID() {
	ctx := s.e.NewContext(nil, nil)
	txid := "ASPB5E72OT2UWSOCQGD5OPT3W4KV4LZZDL7L5MBCC3EBAIJCDHAA"
	s.e.Router().Find(http.MethodGet, "/v1/transaction/"+txid, ctx)
	assert.Equal(s.T(), "/v1/transaction/:txid", ctx.Path())
	assert.Equal(s.T(), txid, ctx.Param("txid"))

	// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
	callsBefore := s.calls
	assert.Equal(s.T(), nil, ctx.Handler()(ctx))
	assert.Equal(s.T(), callsBefore+1, s.calls)
}
func TestTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
