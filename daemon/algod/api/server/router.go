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

// Package server Algod REST API.
//
// API Endpoint for AlgoD Operations.
//
//
//     Schemes: http
//     Host: localhost
//     BasePath: /
//     Version: 0.0.1
//     License:
//     Contact: contact@algorand.com
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Security:
//     - api_key:
//
//     SecurityDefinitions:
//     api_key:
//       type: apiKey
//       name: X-Algo-API-Token
//       in: header
//       description: >-
//         Generated header parameter. This token can be generated using the Goal command line tool. Example value
//         ='b7e384d0317b8050ce45900a94a1931e28540e1f69b2d242b424659c341b4697'
//       required: true
//       x-example: b7e384d0317b8050ce45900a94a1931e28540e1f69b2d242b424659c341b4697
//
// swagger:meta
//---
// Currently, server implementation annotations serve as the API ground truth. From that,
// we use go-swagger to generate a swagger spec.
//
// Autogenerate the swagger json - automatically run by the 'make build' step.
// Base path must be a fully specified package name (else, it seems that swagger feeds a relative path to
// loader.Config.Import(), and that breaks the vendor directory if the source is symlinked from elsewhere)
//go:generate go get github.com/go-swagger/go-swagger/cmd/swagger@v0.25.0
//go:generate swagger generate spec -o="../swagger.json"
//go:generate swagger validate ../swagger.json --stop-on-error
//go:generate sh ./lib/bundle_swagger_json.sh
package server

import (
	"fmt"
	"net"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/algorand/go-algorand/daemon/algod/api/server/common"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib/middlewares"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/routes"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/private"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/util/tokens"
)

const (
	apiV1Tag = "/v1"
)

// wrapCtx passes a common context to each request without a global variable.
func wrapCtx(ctx lib.ReqContext, handler func(lib.ReqContext, echo.Context)) echo.HandlerFunc {
	return func(context echo.Context) error {
		handler(ctx, context)
		return nil
	}
}

// registerHandler registers a set of Routes to the given router.
func registerHandlers(router *echo.Echo, prefix string, routes lib.Routes, ctx lib.ReqContext, m ...echo.MiddlewareFunc) {
	for _, route := range routes {
		r := router.Add(route.Method, prefix+route.Path, wrapCtx(ctx, route.HandlerFunc), m...)
		r.Name = route.Name
	}
}

// TokenHeader is the header where we put the token.
const TokenHeader = "X-Algo-API-Token"

// NewRouter builds and returns a new router with our REST handlers registered.
func NewRouter(logger logging.Logger, node *node.AlgorandFullNode, shutdown <-chan struct{}, apiToken string, adminAPIToken string, listener net.Listener) *echo.Echo {
	if err := tokens.ValidateAPIToken(apiToken); err != nil {
		logger.Errorf("Invalid apiToken was passed to NewRouter ('%s'): %v", apiToken, err)
	}
	if err := tokens.ValidateAPIToken(adminAPIToken); err != nil {
		logger.Errorf("Invalid adminAPIToken was passed to NewRouter ('%s'): %v", adminAPIToken, err)
	}
	adminAuthenticator := middlewares.MakeAuth(TokenHeader, []string{adminAPIToken})
	apiAuthenticator := middlewares.MakeAuth(TokenHeader, []string{adminAPIToken, apiToken})

	e := echo.New()

	e.Listener = listener
	e.HideBanner = true

	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middlewares.MakeLogger(logger))
	e.Use(middlewares.MakeCORS(TokenHeader))

	// Request Context
	ctx := lib.ReqContext{Node: node, Log: logger, Shutdown: shutdown}

	// Register handles / apply authentication middleware

	// Route pprof requests to DefaultServeMux.
	// The auth middleware removes /urlAuth/:token so that it can be routed correctly.
	if node.Config().EnableProfiler {
		e.GET("/debug/pprof/*", echo.WrapHandler(http.DefaultServeMux), adminAuthenticator)
		e.GET(fmt.Sprintf("%s/debug/pprof/*", middlewares.URLAuthPrefix), echo.WrapHandler(http.DefaultServeMux), adminAuthenticator)
	}
	// Registering common routes (no auth)
	registerHandlers(e, "", common.Routes, ctx)

	// Registering v1 routes
	registerHandlers(e, apiV1Tag, routes.V1Routes, ctx, apiAuthenticator)

	// Registering v2 routes
	v2Handler := v2.Handlers{
		Node:     node,
		Log:      logger,
		Shutdown: shutdown,
	}
	generated.RegisterHandlers(e, &v2Handler, apiAuthenticator)
	private.RegisterHandlers(e, &v2Handler, adminAuthenticator)

	return e
}
