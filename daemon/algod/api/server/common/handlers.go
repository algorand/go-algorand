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

package common

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
)

// GenesisJSON is an httpHandler for route GET /genesis
func GenesisJSON(ctx lib.ReqContext, context echo.Context) {
	// swagger:operation GET /genesis GenesisJSON
	//---
	//     Summary: Gets the genesis information
	//     Description: Returns the entire genesis file in json.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         description: The current genesis information
	//         schema: {type: string}
	//       default: { description: Unknown Error }
	w := context.Response().Writer
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(lib.GenesisJSONText))
}

// SwaggerJSON is an httpHandler for route GET /swagger.json
func SwaggerJSON(ctx lib.ReqContext, context echo.Context) {
	// swagger:operation GET /swagger.json SwaggerJSON
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
	w := context.Response().Writer
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(lib.SwaggerSpecJSON))
}

// HealthCheck is an httpHandler for route GET /health
func HealthCheck(ctx lib.ReqContext, context echo.Context) {
	// swagger:operation GET /health HealthCheck
	//---
	//     Summary: Returns OK if healthy.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         description: OK.
	//       default: { description: Unknown Error }
	w := context.Response().Writer
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(nil)
}

// VersionsHandler is an httpHandler for route GET /versions
func VersionsHandler(ctx lib.ReqContext, context echo.Context) {
	// swagger:route GET /versions GetVersion
	//
	// Retrieves the current version
	//
	//     Produces:
	//     - application/json
	//
	//     Schemes: http
	//
	//     Responses:
	//		200: VersionsResponse

	w := context.Response().Writer

	gh := ctx.Node.GenesisHash()
	currentVersion := config.GetCurrentVersion()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := VersionsResponse{
		Body: common.Version{
			Versions:    []string{"v1", "v2"},
			GenesisID:   ctx.Node.GenesisID(),
			GenesisHash: gh[:],
			Build: common.BuildVersion{
				Major:       currentVersion.Major,
				Minor:       currentVersion.Minor,
				BuildNumber: currentVersion.BuildNumber,
				CommitHash:  currentVersion.CommitHash,
				Branch:      currentVersion.Branch,
				Channel:     currentVersion.Channel,
			},
		},
	}
	json.NewEncoder(w).Encode(response.Body)

	return
}

// CORS
func optionsHandler(ctx lib.ReqContext, context echo.Context) {
	context.Response().Writer.WriteHeader(http.StatusOK)
}
