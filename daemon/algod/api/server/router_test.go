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

	// Registering v1 routes
	registerHandlers(e, apiV1Tag, routes.V1Routes, lib.ReqContext{}, nil)

	// Baseline, "method not found".
	func() {
		path := "/v0/this/is/no/endpoint"
		ctx := e.NewContext(nil, nil)
		e.Router().Find(http.MethodGet, path, ctx)
		assert.Equal(t, ctx.Path(), path)
	}()

	// pending transaction extracted parameter
	func() {
		path := "/v1/account/address-param/transactions/pending"
		ctx := e.NewContext(nil, nil)
		e.Router().Find(http.MethodGet, path, ctx)
		assert.Equal(t, ctx.Path(), "/v1/account/:addr/transactions/pending")
		assert.Equal(t, ctx.Param("addr"), "address-param")
	}()
}
