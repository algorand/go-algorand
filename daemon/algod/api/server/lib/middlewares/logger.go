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

package middlewares

import (
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	log "github.com/algorand/go-algorand/logging"
)

// LoggerMiddleware provides some extra state to the logger middleware
type LoggerMiddleware struct {
	log log.Logger
}

// MakeLogger initializes the logger middleware function
func MakeLogger(log log.Logger) echo.MiddlewareFunc {
	logger := LoggerMiddleware{
		log: log,
	}

	return logger.handler
}

// Logger is an echo middleware to add log to the API
func (logger *LoggerMiddleware) handler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) (err error) {
		start := time.Now()

		// Get a reference to the response object.
		res := ctx.Response()
		req := ctx.Request()

		// Propagate the error if the next middleware has a problem
		if err = next(ctx); err != nil {
			ctx.Error(err)
		}

		logger.log.Infof("%s %s %s [%v] \"%s %s %s\" %d %s \"%s\" %s",
			req.RemoteAddr,
			"-",
			"-",
			start,
			req.Method,
			req.RequestURI,
			req.Proto, // string "HTTP/1.1"
			res.Status,
			strconv.FormatInt(res.Size, 10), // bytes_out
			req.UserAgent(),
			time.Since(start),
		)

		return
	}
}
