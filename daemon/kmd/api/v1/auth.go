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

package v1

import (
	"crypto/subtle"
	"net/http"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/tokens"
)

const (
	// KMDTokenHeader is the HTTP header used for the pre-shared auth token
	KMDTokenHeader = "X-KMD-API-Token"
)

func authMiddleware(log logging.Logger, apiToken string) func(http.Handler) http.Handler {
	// Make sure no one is trying to call us with an invalid token
	err := tokens.ValidateAPIToken(apiToken)
	if err != nil {
		log.Fatalf("cannot start server with invalid API token: %v", err)
	}

	apiTokenBytes := []byte(apiToken)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Grab the apiToken from the HTTP header
			providedToken := []byte(r.Header.Get(KMDTokenHeader))

			// Check the token in constant time
			if subtle.ConstantTimeCompare(providedToken, apiTokenBytes) == 1 {
				// Token was correct, keep serving request
				next.ServeHTTP(w, r)
				return
			}

			// Token was incorrect, return an error
			errorResponse(w, http.StatusUnauthorized, errInvalidAPIToken)
		})
	}
}
