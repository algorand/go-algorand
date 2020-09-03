// Copyright (C) 2019-2020 Algorand, Inc.
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
	"errors"
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

var errSuccess = errors.New("unexpected success")
var invalidTokenError = echo.NewHTTPError(http.StatusUnauthorized, InvalidTokenMessage)
var e = echo.New()
var testAPIHeader = "API-Header-Whatever"

// success is the "next" handler, it is only called when auth allows the request to continue
func success(ctx echo.Context) error {
	return errSuccess
}

func TestAuth(t *testing.T) {
	tokens := []string{"token1", "token2"}

	tests := []struct {
		name           string
		url            string
		header         string
		token          string
		method         string
		expectResponse error
		finalPath      string
	}{
		{
			"Valid token (1)",
			"N/A",
			testAPIHeader,
			tokens[0],
			"GET",
			errSuccess,
			"",
		},
		{
			"Valid token (2)",
			"N/A",
			testAPIHeader,
			tokens[1],
			"GET",
			errSuccess,
			"",
		},
		{
			"Valid token Bearer Format (1)",
			"N/A",
			"Authorization",
			"Bearer " + tokens[0],
			"GET",
			errSuccess,
			"",
		},
		{
			"Valid token Bearer Format (2)",
			"N/A",
			"Authorization",
			"Bearer " + tokens[1],
			"GET",
			errSuccess,
			"",
		},
		{
			"Invalid token",
			"N/A",
			testAPIHeader,
			"invalid_token",
			"GET",
			invalidTokenError,
			"",
		},
		{
			"Invalid token Bearer Format",
			"N/A",
			"Authorization",
			"Bearer invalid_token",
			"GET",
			invalidTokenError,
			"",
		},
		{
			"Missing token",
			"N/A",
			"",
			"",
			"GET",
			invalidTokenError,
			"",
		},
		{
			"Invalid token + OPTIONS",
			"N/A",
			testAPIHeader,
			"invalid_token",
			"OPTIONS",
			errSuccess,
			"",
		},
		{
			"Invalid bearer token + OPTIONS",
			"N/A",
			"Authorization",
			"Bearer invalid_token",
			"OPTIONS",
			errSuccess,
			"",
		},
		{
			"Token in url (1)",
			"http://my-node.com:80/urlAuth/" + tokens[0] + "/v2/status",
			"",
			tokens[0],
			"GET",
			errSuccess,
			"/v2/status",
		},
		{
			"Token in url (2)",
			"http://my-node.com:80/urlAuth/" + tokens[1] + "/v2/status",
			"",
			tokens[1],
			"GET",
			errSuccess,
			"/v2/status",
		},
		{
			"Invalid token in url",
			"http://my-node.com:80/urlAuth/invalid_token/v2/status",
			"",
			"invalid_token",
			"GET",
			invalidTokenError,
			"",
		},
	}

	authFn := MakeAuth(testAPIHeader, tokens)
	handler := authFn(success)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest(test.method, test.url, nil)
			if test.header != "" {
				req.Header.Set(test.header, test.token)
			}
			ctx := e.NewContext(req, nil)

			// There is no router to update the context based on the url, so do it manually.
			if test.header == "" && test.token != "" {
				ctx.SetParamNames(TokenPathParam)
				ctx.SetParamValues(test.token)
			}
			ctx.SetPath("")

			err := handler(ctx)
			require.Equal(t, test.expectResponse, err, test.name)

			// In some cases the auth rewrites the path, make sure the path has been rewritten
			if test.finalPath != "" {
				require.Equal(t, test.finalPath, ctx.Path())
				require.Equal(t, test.finalPath, ctx.Request().URL.Path)
			}
		})
	}
}
