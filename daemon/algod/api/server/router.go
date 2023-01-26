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

// Package server Algod REST API.
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
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/experimental"
	npprivate "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/nonparticipating/private"
	nppublic "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/nonparticipating/public"
	pprivate "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/participating/private"
	ppublic "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/participating/public"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/util/tokens"
)

const (
	apiV1Tag = "/v1"
	// TokenHeader is the header where we put the token.
	TokenHeader = "X-Algo-API-Token"
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

// NewRouter builds and returns a new router with our REST handlers registered.
func NewRouter(logger logging.Logger, node *node.AlgorandFullNode, shutdown <-chan struct{}, apiToken string, adminAPIToken string, listener net.Listener, numConnectionsLimit uint64) *echo.Echo {
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

	e.Pre(
		middlewares.MakeConnectionLimiter(numConnectionsLimit),
		middleware.RemoveTrailingSlash())
	e.Use(
		middlewares.MakeLogger(logger),
		middlewares.MakeCORS(TokenHeader))

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
		Node:     apiNode{node},
		Log:      logger,
		Shutdown: shutdown,
	}
	nppublic.RegisterHandlers(e, &v2Handler, apiAuthenticator)
	npprivate.RegisterHandlers(e, &v2Handler, adminAuthenticator)
	ppublic.RegisterHandlers(e, &v2Handler, apiAuthenticator)
	pprivate.RegisterHandlers(e, &v2Handler, adminAuthenticator)

	if node.Config().EnableExperimentalAPI {
		experimental.RegisterHandlers(e, &v2Handler, apiAuthenticator)
	}

	return e
}

// apiNode wraps the AlgorandFullNode to provide v2.NodeInterface.
type apiNode struct{ *node.AlgorandFullNode }

func (n apiNode) LedgerForAPI() v2.LedgerForAPI { return n.Ledger() }
