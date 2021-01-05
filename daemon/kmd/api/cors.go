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

package api

import (
	"crypto/subtle"
	"net/http"

	v1 "github.com/algorand/go-algorand/daemon/kmd/api/v1"
)

const allowedMethods = "GET, POST, DELETE, OPTIONS"
const allowedHeaders = v1.KMDTokenHeader + ", Content-Type"

func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this origin is allowed to talk to kmd
			origin := r.Header.Get("Origin")
			found := ""
			for _, allowedOrigin := range allowedOrigins {
				if subtle.ConstantTimeCompare([]byte(origin), []byte(allowedOrigin)) == 1 {
					found = allowedOrigin
					break
				} else if allowedOrigin == "*" {
					found = origin
					break
				}
			}

			// If one of the allowed origins matched the header, set the appropriate
			// CORS headers. Continue the request regardless, since we might not be
			// talking to a browser.
			if found != "" {
				w.Header().Set("Access-Control-Allow-Origin", found)
				w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
				w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
			}

			// Continue serving the request
			next.ServeHTTP(w, r)
		})
	}
}
