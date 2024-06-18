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

package common

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	"github.com/algorand/go-algorand/node"
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
	_, _ = w.Write([]byte(api.SwaggerSpecJSONEmbed))
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

// Ready is a httpHandler for route GET /ready
// it serves "readiness" probe on if the node is healthy and fully caught-up.
func Ready(ctx lib.ReqContext, context echo.Context) {
	// swagger:operation GET /ready Ready
	//---
	//     Summary: Returns OK if healthy and fully caught up.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         description: OK.
	//       500:
	//         description: Internal Error.
	//       503:
	//         description: Node not ready yet.
	//       default: { description: Unknown Error }
	w := context.Response().Writer
	w.Header().Set("Content-Type", "application/json")

	stat, err := ctx.Node.Status()
	code := http.StatusOK

	// isReadyFromStat checks the `Node.Status()` result
	// and decide if the node is at the latest round
	// must satisfy following sub conditions:
	// 1. the node is not in a fast-catchup stage
	// 2. the node's time since last round should be [0, deadline),
	//    while deadline = agreement.DefaultDeadlineTimeout = 17s
	// 3. the node's catchup time is 0
	isReadyFromStat := func(status node.StatusReport) bool {
		timeSinceLastRound := status.TimeSinceLastRound().Milliseconds()

		return len(status.Catchpoint) == 0 &&
			timeSinceLastRound >= 0 &&
			timeSinceLastRound < agreement.DefaultDeadlineTimeout().Milliseconds() &&
			status.CatchupTime.Milliseconds() == 0
	}

	if err != nil {
		code = http.StatusInternalServerError
		ctx.Log.Error(err)
	} else if stat.StoppedAtUnsupportedRound {
		code = http.StatusInternalServerError
		err = fmt.Errorf("stopped at an unsupported round")
		ctx.Log.Error(err)
	} else if !isReadyFromStat(stat) {
		code = http.StatusServiceUnavailable
		err = fmt.Errorf("ready failed as the node is catching up")
		ctx.Log.Info(err)
	}

	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(nil)
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
			Versions:    []string{"v2"},
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
}

// CORS
func optionsHandler(ctx lib.ReqContext, context echo.Context) {
	context.Response().Writer.WriteHeader(http.StatusOK)
}
