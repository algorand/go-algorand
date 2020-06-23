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

package server

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/routes"
)

func TestRoute(t *testing.T) {
	e := echo.New()
	calls := 0

	handler := func(context lib.ReqContext, context2 echo.Context) {
		calls++
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
	registerHandlers(e, apiV1Tag, v1RoutesCopy, lib.ReqContext{})

	// Baseline, unknown endpoint
	func() {
		ctx := e.NewContext(nil, nil)
		e.Router().Find(http.MethodGet, "/v0/this/is/no/endpoint", ctx)
		assert.Equal(t, ctx.Handler()(ctx), echo.ErrNotFound)
		assert.Equal(t, calls, 0)
	}()

	// pending transaction extracted parameter
	func() {
		ctx := e.NewContext(nil, nil)
		e.Router().Find(http.MethodGet, "/v1/account/address-param/transactions/pending", ctx)
		assert.Equal(t, ctx.Path(), "/v1/account/:addr/transactions/pending")
		assert.Equal(t, ctx.Param("addr"), "address-param")

		// Ensure that a handler in the route array was called by checking that the 'calls' variable is incremented.
		callsBefore := calls
		ctx.Handler()(ctx)
		assert.Equal(t, callsBefore + 1, calls)
	}()
}
