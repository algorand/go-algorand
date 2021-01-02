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
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/util/metrics"
)

// Metrics returns data collected by util/metrics
func Metrics(ctx lib.ReqContext, context echo.Context) {
	// swagger:operation GET /metrics Metrics
	//---
	//     Summary: Return metrics about algod functioning.
	//     Produces:
	//     - text/plain
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         description: text with \#-comments and key:value lines
	//       404:
	//         description: metrics were compiled out
	w := context.Response().Writer
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	var buf strings.Builder
	metrics.DefaultRegistry().WriteMetrics(&buf, "")
	w.Write([]byte(buf.String()))
}

func init() {
	Routes = append(Routes,
		lib.Route{
			Name:        "metrics",
			Method:      "GET",
			Path:        "/metrics",
			HandlerFunc: Metrics,
		},
	)
}
