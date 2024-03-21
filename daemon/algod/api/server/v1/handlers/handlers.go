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

package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
)

// V1Sunset is a generic handler for all v1 routes that shows the sunset message.
func V1Sunset(ctx lib.ReqContext, context echo.Context) {
	w := context.Response().Writer

	lib.ErrorResponse(w, http.StatusGone, errors.New(errV1Sunset), errV1Sunset, ctx.Log)
}
