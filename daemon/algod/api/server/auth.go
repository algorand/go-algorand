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
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/daemon/algod/api/server/lib/middlewares"
	"github.com/algorand/go-algorand/logging"
)

const urlAuthFormatter = "/urlAuth/%s"
const debugRouteName = "debug"

// AuthRoutes define the mapping of authentication key to allowed routes.
type AuthRoutes map[string]map[echo.Route]echo.HandlerFunc

// Auth is the authentication layer
type Auth struct {
	log  logging.Logger
	echo *echo.Echo
}

// MakeAuth create an authentication object
func MakeAuth(log logging.Logger, e *echo.Echo) *Auth {
	return &Auth{
		log:  log,
		echo: e,
	}
}

// RegisterHandlers registers the given authentication routes
func (auth *Auth) RegisterHandlers(authRoutes AuthRoutes) {
	routeTokens := make(map[echo.Route][]string)

	// for each unique route, find the list of tokens.
	for token, routes := range authRoutes {
		for route := range routes {
			routeTokens[route] = append(routeTokens[route], token)
		}
	}
	for _, routes := range authRoutes {
		for route, routeFunction := range routes {
			auth.echo.Add(route.Method, route.Path, makeAuthenticatedHandler(routeTokens[route], routeFunction, route).GetHandler())
		}
	}

}

type authenticatedHandler struct {
	tokens  [][]byte
	handler echo.HandlerFunc
	route   echo.Route
}

func makeAuthenticatedHandler(tokens []string, handler echo.HandlerFunc, route echo.Route) *authenticatedHandler {
	authHandler := &authenticatedHandler{
		handler: handler,
		route:   route,
	}
	for _, token := range tokens {
		authHandler.tokens = append(authHandler.tokens, []byte(token))
	}

	return authHandler
}
func (h *authenticatedHandler) GetHandler() echo.HandlerFunc {
	if h.route.Path == "/urlAuth/:token/debug/pprof/*" {
		return h.DebugHandler
	}
	return h.Handler
}

func (h *authenticatedHandler) DebugHandler(ctx echo.Context) error {
	var providedToken []byte
	// Handle debug routes with /urlAuth/:token prefix.
	if ctx.Param("token") != "" {
		// For debug routes, we place the apiToken in the path itself
		providedToken = []byte(ctx.Param("token"))

		// Internally, pprof matches exact routes and won't match our APIToken.
		// We need to rewrite the requested path to exclude the token prefix.
		// https://git.io/fp2NO
		authPrefix := fmt.Sprintf(urlAuthFormatter, providedToken)
		// /urlAuth/[token string]/debug/pprof/ => /debug/pprof/
		newPath := strings.TrimPrefix(ctx.Request().URL.Path, authPrefix)
		ctx.SetPath(newPath)
		ctx.Request().URL.Path = newPath
	}

	matchingAuthIndex := -1
	// Check the token in constant time
	for i, privAuth := range h.tokens {
		compareResult := subtle.ConstantTimeCompare(providedToken, privAuth)
		// if compareResult is 1, we want to update matchingAuthIndex with i. otherwise, we want to keep it as is.
		matchingAuthIndex = compareResult*i + matchingAuthIndex*(1-compareResult)
	}

	if matchingAuthIndex >= 0 {
		// Token was correct, keep serving request
		return h.handler(ctx)
	}

	return echo.NewHTTPError(http.StatusUnauthorized, "Invalid API Token")
}
func (h *authenticatedHandler) Handler(ctx echo.Context) error {
	// Grab the apiToken from the HTTP header, or as a bearer token
	providedToken := []byte(ctx.Request().Header.Get(middlewares.TokenHeader))
	if len(providedToken) == 0 {
		// Accept tokens provided in a bearer token format.
		authentication := strings.SplitN(ctx.Request().Header.Get("Authorization"), " ", 2)
		if len(authentication) == 2 && strings.EqualFold("Bearer", authentication[0]) {
			providedToken = []byte(authentication[1])
		}
	}

	matchingAuthIndex := -1
	// Check the token in constant time
	for i, privAuth := range h.tokens {
		compareResult := subtle.ConstantTimeCompare(providedToken, privAuth)
		// if compareResult is 1, we want to update matchingAuthIndex with i. otherwise, we want to keep it as is.
		matchingAuthIndex = compareResult*i + matchingAuthIndex*(1-compareResult)
	}

	if matchingAuthIndex >= 0 {
		// Token was correct, keep serving request
		return h.handler(ctx)
	}

	return echo.NewHTTPError(http.StatusUnauthorized, "Invalid API Token")
}
