package middlewares

import (
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

var successError = errors.New("unexpected success")
var invalidTokenError = echo.NewHTTPError(http.StatusUnauthorized, InvalidTokenMessage)
var e = echo.New()
var testAPIHeader = "API-Header-Whatever"

// success is the "next" handler, it is only called when auth allows the request to continue
func success(ctx echo.Context) error {
	return successError
}

func TestAuth(t *testing.T) {
	tokens := []string{ "token1", "token2" }

	tests := []struct {
		name string
		url string
		header string
		token string
		method string
		expectResponse error
		finalPath string
	} {
		{
			"Valid token (1)",
			"N/A",
			testAPIHeader,
			tokens[0],
			"GET",
			successError,
			"",
		},
		{
			"Valid token (2)",
			"N/A",
			testAPIHeader,
			tokens[1],
			"GET",
			successError,
			"",
		},
		{
			"Valid token Bearer Format (1)",
			"N/A",
			"Authorization",
			"Bearer " + tokens[0],
			"GET",
			successError,
			"",
		},
		{
			"Valid token Bearer Format (2)",
			"N/A",
			"Authorization",
			"Bearer " + tokens[1],
			"GET",
			successError,
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
			successError,
			"",
		},
		{
			"Invalid bearer token + OPTIONS",
			"N/A",
			"Authorization",
			"Bearer invalid_token",
			"OPTIONS",
			successError,
			"",
		},
		{
			"Token in url (1)",
			"http://my-node.com:80/urlAuth/" + tokens[0] + "/v2/status",
			"",
			tokens[0],
			"GET",
			successError,
			"/v2/status",
		},
		{
			"Token in url (2)",
			"http://my-node.com:80/urlAuth/" + tokens[1] + "/v2/status",
			"",
			tokens[1],
			"GET",
			successError,
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
		req, _ := http.NewRequest(test.method, test.url, nil)
		if test.header != "" {
			req.Header.Set(test.header, test.token)
		}
		ctx := e.NewContext(req, nil)

		// There is no router to update the context based on the url, so do it manually.
		if test.header == "" && test.token != "" {
			ctx.SetParamNames("token")
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
	}
}
