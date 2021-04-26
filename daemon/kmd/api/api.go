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

// Package api for KMD HTTP API
//
// API for KMD (Key Management Daemon)
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
//       name: X-KMD-API-Token
//       in: header
//       description: >-
//         Generated header parameter. This value can be found in `/kmd/data/dir/kmd.token`. Example value:
//         '330b2e4fc9b20f4f89812cf87f1dabeb716d23e3f11aec97a61ff5f750563b78'
//       required: true
//       x-example: 330b2e4fc9b20f4f89812cf87f1dabeb716d23e3f11aec97a61ff5f750563b78
//
// swagger:meta
//---
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
//go:generate go get github.com/go-swagger/go-swagger/cmd/swagger@v0.25.0
//go:generate swagger generate spec -m -o="./swagger.json"
//go:generate swagger validate ./swagger.json --stop-on-error
//go:generate sh ../lib/kmdapi/bundle_swagger_json.sh
package api

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/daemon/kmd/api/v1"
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

// optionsHandler is a dummy endpoint that catches all OPTIONS requests. We
// need this because middleware only triggers if we match a route.
func optionsHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
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

// Handler returns the root mux router for the kmd API. It sets up handlers on
// subrouters specific to each API version.
func Handler(sm *session.Manager, log logging.Logger, allowedOrigins []string, apiToken string, reqCB func()) *mux.Router {
	rootRouter := mux.NewRouter()

	// Send the appropriate CORS headers
	rootRouter.Use(corsMiddleware(allowedOrigins))

	// Handle OPTIONS requests
	rootRouter.Methods("OPTIONS").HandlerFunc(optionsHandler)

	// The /versions endpoint has no version, so we register it here. /versions
	// has no auth, because it doesn't return anything sensitive, and auth is
	// version-specific. The same applies for /swagger.json.
	rootRouter.HandleFunc("/versions", versionsHandler)
	rootRouter.HandleFunc("/swagger.json", SwaggerHandler)

	// Handle API V1 routes at /v1/<...>
	v1Router := rootRouter.PathPrefix(fmt.Sprintf("/%s", apiV1Tag)).Subrouter()
	v1.RegisterHandlers(v1Router, sm, log, apiToken, reqCB)

	return rootRouter
}
