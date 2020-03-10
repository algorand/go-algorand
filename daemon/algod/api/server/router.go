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
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/daemon/algod/api/server/common"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib/middlewares"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/routes"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
)

const (
	apiV1Tag              = "v1"
	debugRouteName        = "debug"
	pprofEndpointPrefix   = "/debug/pprof/"
	urlAuthEndpointPrefix = "/urlAuth/{apiToken:[0-9a-f]+}"
)

// wrapCtx passes a common context to each request without a global variable.
func wrapCtx(ctx lib.ReqContext, handler func(lib.ReqContext, http.ResponseWriter, *http.Request)) echo.HandlerFunc {
	return func(context echo.Context) error {
		handler(ctx, context.Response(), context.Request())
		return nil
	}
}

// registerHandler registers a set of Routes to [router]. if [prefix] is not empty, it
// registers the routes to a new sub-router [prefix]
func registerHandlers(router *echo.Echo, prefix string, routes lib.Routes, ctx lib.ReqContext) {
	for _, route := range routes {
		r := router.Add(route.Method, prefix + route.Path, wrapCtx(ctx, route.HandlerFunc))
		r.Name = route.Name
	}
}

// NewRouter builds and returns a new router from routes
func ConfigureRouter(logger logging.Logger, node *node.AlgorandFullNode, shutdown <-chan struct{}, apiToken string, e *echo.Echo) {
	e.Use(echo.WrapMiddleware(middlewares.Logger(logger)))
	// TODO: Rewrite the auth middleware to support the new auth requirements.
	//e.Use(echo.WrapMiddleware(middlewares.Auth(logger, apiToken)))
	e.Use(echo.WrapMiddleware(middlewares.CORS))

	// We could use these out of the box instead of writing our own.
	//e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
	//	Format: "${remote_ip} - - ${time_rfc3339_nano} ${method} ${uri} ${protocol} ${status} ${bytes_in} ${user_agent} ${latency}\n",
	//}))
	//e.Use(middleware.CORS())

	// Request Context
	ctx := lib.ReqContext{Node: node, Log: logger, Shutdown: shutdown}

	// Route pprof requests
	if node.Config().EnableProfiler {
		// Registers /debug/pprof handler under root path and under /urlAuth path
		// to support header or url-provided token.
		//router.PathPrefix(pprofEndpointPrefix).Handler(http.DefaultServeMux)
		e.GET(pprofEndpointPrefix + "/*", echo.WrapHandler(http.DefaultServeMux))

		//urlAuthRouter := router.PathPrefix(urlAuthEndpointPrefix)
		//urlAuthRouter.PathPrefix(pprofEndpointPrefix).Handler(http.DefaultServeMux).Name(debugRouteName)
		grp := e.Group(urlAuthEndpointPrefix)
		route := grp.GET(pprofEndpointPrefix + "/*", echo.WrapHandler(http.DefaultServeMux))
		route.Name = debugRouteName
	}

	// Registering common routes
	registerHandlers(e, "", common.Routes, ctx)

	// Registering v1 routes
	registerHandlers(e, apiV1Tag, routes.V1Routes, ctx)

	// Registering v2 routes
	generated.RegisterHandlers(e, &v2.V2Handlers{})
}
