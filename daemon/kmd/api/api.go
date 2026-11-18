// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

// Package api for KMD HTTP API
//
// API for KMD (Key Management Daemon)
//
//	Schemes: http
//	Host: localhost
//	BasePath: /
//	Version: 0.0.1
//	License:
//	Contact: contact@algorand.com
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Security:
//	- api_key:
//
//	SecurityDefinitions:
//	api_key:
//	  type: apiKey
//	  name: X-KMD-API-Token
//	  in: header
//	  description: >-
//	    Generated header parameter. This value can be found in `/kmd/data/dir/kmd.token`. Example value:
//	    '330b2e4fc9b20f4f89812cf87f1dabeb716d23e3f11aec97a61ff5f750563b78'
//	  required: true
//	  x-example: 330b2e4fc9b20f4f89812cf87f1dabeb716d23e3f11aec97a61ff5f750563b78
//
// swagger:meta
// ---
// IF YOU MODIFY SUBPACKAGES: IMPORTANT
// MAKE SURE YOU REGENERATE THE SWAGGER SPEC (using go:generate)
// MAKE SURE IT VALIDATES
//
// Currently, server implementation annotations serve
// as the API ground truth. From that, we use go-swagger
// to generate a swagger spec.
//
// Autogenerate the swagger json.
// Base path must be a fully specified package name (else, it seems that swagger feeds a relative path to
// loader.Config.Import(), and that breaks the vendor directory if the source is symlinked from elsewhere)
//
//go:generate go run github.com/algorand/go-swagger/cmd/swagger@v0.0.0-20251018003531-2ea7c750dcac generate spec -m --transparent-aliases -o="./swagger.json"
//go:generate go run github.com/algorand/go-swagger/cmd/swagger@v0.0.0-20251018003531-2ea7c750dcac validate ./swagger.json --stop-on-error
//go:generate sh ../lib/kmdapi/bundle_swagger_json.sh
package api

import (
	"net/http"

	v1 "github.com/algorand/go-algorand/daemon/kmd/api/v1"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/daemon/kmd/session"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

const (
	apiV1Tag = "v1"
)

var supportedAPIVersions = []string{apiV1Tag}

// The /versions endpoint is one of two non-versioned API endpoints, since its
// response tells us which API versions are supported (the other is /swagger.json)
func versionsHandler(w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /versions GetVersion
	//---
	//     Summary: Retrieves the current version
	//     Produces:
	//     - application/json
	//     Parameters:
	//     - name: Versions Request
	//       in: body
	//       required: false
	//       schema:
	//         "$ref": "#/definitions/VersionsRequest"
	//     Responses:
	//       "200":
	//         "$ref": "#/responses/VersionsResponse"
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := kmdapi.VersionsResponse{
		Versions: supportedAPIVersions,
	}
	w.Write(protocol.EncodeJSON(response))
}

// optionsMiddleware answers every OPTIONS request (CORS preflight) with 200
// before routing, so unknown paths still return 404 for other methods.
func optionsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SwaggerHandler is an httpHandler for route GET /swagger.json, and at this point
// is not versioned.
func SwaggerHandler(w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /swagger.json SwaggerHandler
	//---
	//     Summary: Gets the current swagger spec.
	//     Description: Returns the entire swagger spec in json.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         description: The current swagger spec
	//         schema: {type: string}
	//       default: { description: Unknown Error }
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(kmdapi.SwaggerSpecJSON))
}

// Handler returns the root HTTP handler for the kmd API. It sets up handlers
// for each API version and applies middleware.
func Handler(sm *session.Manager, log logging.Logger, allowedOrigins []string, apiToken string, pnaHeader bool, reqCB func()) http.Handler {
	mux := http.NewServeMux()

	// Every request matches at least this catch-all, so ServeMux returns 404
	// without first searching all methods to decide between 404 and 405.
	mux.Handle("/", http.NotFoundHandler())

	// The /versions endpoint has no version, so we register it here. /versions
	// has no auth, because it doesn't return anything sensitive, and auth is
	// version-specific. The same applies for /swagger.json. Neither pattern
	// names a method, so both accept any method.
	mux.HandleFunc("/versions", versionsHandler)
	mux.HandleFunc("/swagger.json", SwaggerHandler)

	// Handle API V1 routes at /v1/<...>
	v1.RegisterHandlers(mux, "/"+apiV1Tag, sm, log, apiToken, reqCB)

	// Handle OPTIONS requests, then send the appropriate CORS headers
	var handler http.Handler = mux
	handler = optionsMiddleware(handler)
	handler = corsMiddleware(allowedOrigins)(handler)
	if pnaHeader {
		handler = AllowPNA()(handler)
	}

	return handler
}
