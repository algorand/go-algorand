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

package middlewares

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// MakeConnectionLimiter makes an echo middleware that limits the number of
// simultaneous connections. All connections above the limit will be returned
// the 429 Too Many Requests http error.
func MakeConnectionLimiter(limit uint64) echo.MiddlewareFunc {
	sem := make(chan struct{}, limit)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			select {
			case sem <- struct{}{}:
				defer func() {
					// If we fail to read from `sem`, just continue.
					select {
					case <-sem:
					default:
					}
				}()
				return next(ctx)
			default:
				return ctx.NoContent(http.StatusTooManyRequests)
			}
		}
	}
}
