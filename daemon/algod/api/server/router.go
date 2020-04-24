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
//go:generate swagger generate spec -o="../swagger.json"
//go:generate swagger validate ../swagger.json --stop-on-error
//go:generate ./lib/bundle_swagger_json.sh
package server

import (
	"net"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/algorand/go-algorand/daemon/algod/api/server/common"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib/middlewares"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/routes"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2"
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

// registerHandler registers a set of Routes to [router]. if [prefix] is not empty, it
// registers the routes to a new sub-router [prefix]
func registerHandlers(router *echo.Echo, prefix string, routes lib.Routes, ctx lib.ReqContext) {
	for _, route := range routes {
		if len(route.Path) == 0 {
			continue
		}
		r := router.Add(route.Method, prefix+route.Path, wrapCtx(ctx, route.HandlerFunc))
		r.Name = route.Name
	}
}

func makeAuthRoutes(ctx lib.ReqContext, apiToken string, adminAPIToken string, enableProfiler bool) AuthRoutes {
	authRoutes := make(AuthRoutes)
	noAuthRoutes := make(map[echo.Route]echo.HandlerFunc)
	defaultAuthRoutes := make(map[echo.Route]echo.HandlerFunc)
	adminAuthRoutes := make(map[echo.Route]echo.HandlerFunc)
	authRoutes[""] = noAuthRoutes
	authRoutes[apiToken] = defaultAuthRoutes
	authRoutes[adminAPIToken] = adminAuthRoutes
	for _, route := range common.Routes {
		if route.NoAuth {
			noAuthRoutes[echo.Route{Method: route.Method, Path: route.Path}] = wrapCtx(ctx, route.HandlerFunc)
			continue
		}
		defaultAuthRoutes[echo.Route{Method: route.Method, Path: route.Path}] = wrapCtx(ctx, route.HandlerFunc)
		adminAuthRoutes[echo.Route{Method: route.Method, Path: route.Path}] = wrapCtx(ctx, route.HandlerFunc)
	}
	for _, route := range routes.V1Routes {
		defaultAuthRoutes[echo.Route{Method: route.Method, Path: apiV1Tag + route.Path}] = wrapCtx(ctx, route.HandlerFunc)
		adminAuthRoutes[echo.Route{Method: route.Method, Path: apiV1Tag + route.Path}] = wrapCtx(ctx, route.HandlerFunc)
	}

	// pick the "regular" endpoints
	for route, handler := range v2.GetRoutes(ctx, false) {
		defaultAuthRoutes[route] = handler
		adminAuthRoutes[route] = handler
	}

	// pick the "admin" endpoints
	for route, handler := range v2.GetRoutes(ctx, true) {
		adminAuthRoutes[route] = handler
	}
	if enableProfiler {
		adminAuthRoutes[echo.Route{Method: echo.GET, Path: "/urlAuth/:token/debug/pprof/*"}] = echo.WrapHandler(http.DefaultServeMux)
		adminAuthRoutes[echo.Route{Method: echo.GET, Path: "/debug/pprof/*"}] = echo.WrapHandler(http.DefaultServeMux)
	}
	return authRoutes
}

// NewRouter builds and returns a new router with our REST handlers registered.
func NewRouter(logger logging.Logger, node *node.AlgorandFullNode, shutdown <-chan struct{}, apiToken string, adminAPIToken string, listener net.Listener) *echo.Echo {
	if err := tokens.ValidateAPIToken(apiToken); err != nil {
		logger.Errorf("Invalid apiToken was passed to NewRouter ('%s'): %v", apiToken, err)
	}
	if err := tokens.ValidateAPIToken(adminAPIToken); err != nil {
		logger.Errorf("Invalid adminAPIToken was passed to NewRouter ('%s'): %v", adminAPIToken, err)
	}

	e := echo.New()

	e.Listener = listener
	e.HideBanner = true

	e.Pre(middleware.RemoveTrailingSlash())

	authenticator := MakeAuth(logger, e)
	e.Use(echo.WrapMiddleware(middlewares.Logger(logger)))
	e.Use(echo.WrapMiddleware(middlewares.CORS))

	// Note: Echo has builtin middleware for logging / CORS that we should investigate:
	//e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
	//	Format: "${remote_ip} - - ${time_rfc3339_nano} ${method} ${uri} ${protocol} ${status} ${bytes_in} ${user_agent} ${latency}\n",
	//}))
	//e.Use(middleware.CORS())

	// Request Context
	ctx := lib.ReqContext{Node: node, Log: logger, Shutdown: shutdown}

	// Register handles
	authenticator.RegisterHandlers(makeAuthRoutes(ctx, apiToken, adminAPIToken, node.Config().EnableProfiler))

	return e
}
