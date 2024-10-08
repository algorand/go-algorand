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

// Package server Algod REST API.
package server

import (
	"fmt"
	"net"
	"net/http"

	"golang.org/x/sync/semaphore"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/algorand/go-algorand/daemon/algod/api/server/common"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib/middlewares"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/routes"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/data"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/experimental"
	npprivate "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/nonparticipating/private"
	nppublic "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/nonparticipating/public"
	pprivate "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/participating/private"
	ppublic "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/participating/public"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/util/tokens"
)

// APINodeInterface describes all the node methods required by common and v2 APIs, and the server/router
type APINodeInterface interface {
	lib.NodeInterface
	v2.NodeInterface
}

const (
	apiV1Tag = "/v1"
	// TokenHeader is the header where we put the token.
	TokenHeader = "X-Algo-API-Token"
	// MaxRequestBodyBytes is the maximum request body size that we allow in our APIs.
	MaxRequestBodyBytes = "10MB"
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
func NewRouter(logger logging.Logger, node APINodeInterface, shutdown <-chan struct{}, apiToken string, adminAPIToken string, listener net.Listener, numConnectionsLimit uint64) *echo.Echo {
	// check admin token and init admin middleware
	if err := tokens.ValidateAPIToken(adminAPIToken); err != nil {
		logger.Errorf("Invalid adminAPIToken was passed to NewRouter ('%s'): %v", adminAPIToken, err)
	}
	adminMiddleware := []echo.MiddlewareFunc{
		middlewares.MakeAuth(TokenHeader, []string{adminAPIToken}),
	}

	// check public api tokens and init public middleware
	publicMiddleware := []echo.MiddlewareFunc{
		middleware.BodyLimit(MaxRequestBodyBytes),
	}
	if apiToken == "" {
		logger.Warn("Running with public API authentication disabled")
	} else {
		if err := tokens.ValidateAPIToken(apiToken); err != nil {
			logger.Errorf("Invalid apiToken was passed to NewRouter ('%s'): %v", apiToken, err)
		}
		publicMiddleware = append(publicMiddleware, middlewares.MakeAuth(TokenHeader, []string{adminAPIToken, apiToken}))

	}

	e := echo.New()

	e.Listener = listener
	e.HideBanner = true

	e.Pre(
		middlewares.MakeConnectionLimiter(numConnectionsLimit),
		middleware.RemoveTrailingSlash())
	e.Use(
		middlewares.MakeLogger(logger),
	)
	// Optional middleware for Private Network Access Header (PNA). Must come before CORS middleware.
	if node.Config().EnablePrivateNetworkAccessHeader {
		e.Use(middlewares.MakePNA())
	}
	e.Use(
		middlewares.MakeCORS(TokenHeader),
	)

	// Request Context
	ctx := lib.ReqContext{Node: node, Log: logger, Shutdown: shutdown}

	// Register handles / apply authentication middleware

	// Route pprof requests to DefaultServeMux.
	// The auth middleware removes /urlAuth/:token so that it can be routed correctly.
	if node.Config().EnableProfiler {
		e.GET("/debug/pprof/*", echo.WrapHandler(http.DefaultServeMux), adminMiddleware...)
		e.GET(fmt.Sprintf("%s/debug/pprof/*", middlewares.URLAuthPrefix), echo.WrapHandler(http.DefaultServeMux), adminMiddleware...)
	}
	// Registering common routes (no auth)
	registerHandlers(e, "", common.Routes, ctx)

	// Registering v1 routes
	registerHandlers(e, apiV1Tag, routes.V1Routes, ctx, publicMiddleware...)

	// Registering v2 routes
	v2Handler := v2.Handlers{
		Node:          node,
		Log:           logger,
		Shutdown:      shutdown,
		KeygenLimiter: semaphore.NewWeighted(1),
	}
	nppublic.RegisterHandlers(e, &v2Handler, publicMiddleware...)
	npprivate.RegisterHandlers(e, &v2Handler, adminMiddleware...)
	ppublic.RegisterHandlers(e, &v2Handler, publicMiddleware...)
	pprivate.RegisterHandlers(e, &v2Handler, adminMiddleware...)

	if node.Config().EnableFollowMode {
		data.RegisterHandlers(e, &v2Handler, publicMiddleware...)
	}

	if node.Config().EnableExperimentalAPI {
		experimental.RegisterHandlers(e, &v2Handler, publicMiddleware...)
	}

	return e
}

// FollowerNode wraps the AlgorandFollowerNode to provide v2.NodeInterface.
type FollowerNode struct{ *node.AlgorandFollowerNode }

// LedgerForAPI implements the v2.Handlers interface
func (n FollowerNode) LedgerForAPI() v2.LedgerForAPI { return n.Ledger() }

// APINode wraps the AlgorandFullNode to provide v2.NodeInterface.
type APINode struct{ *node.AlgorandFullNode }

// LedgerForAPI implements the v2.Handlers interface
func (n APINode) LedgerForAPI() v2.LedgerForAPI { return n.Ledger() }
