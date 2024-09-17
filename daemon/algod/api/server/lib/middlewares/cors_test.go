package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestMakeCORS(t *testing.T) {
	e := echo.New()
	tokenHeader := "X-Algo-API-Token"
	corsMiddleware := MakeCORS(tokenHeader)

	testCases := []struct {
		name            string
		method          string
		headers         map[string]string
		expectedStatus  int
		expectedHeaders map[string]string
	}{
		{
			name:   "OPTIONS request",
			method: http.MethodOptions,
			headers: map[string]string{
				"Origin":                         "http://algorand.com",
				"Access-Control-Request-Headers": "Content-Type," + tokenHeader,
			},
			expectedStatus: http.StatusNoContent,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
				"Access-Control-Allow-Headers": tokenHeader + ",Content-Type",
			},
		},
		{
			name:   "GET request",
			method: http.MethodGet,
			headers: map[string]string{
				"Origin": "http://algorand.com",
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/health", nil)
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := corsMiddleware(func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			})

			err := handler(c)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
			for key, value := range tc.expectedHeaders {
				assert.Equal(t, value, rec.Header().Get(key))
			}
		})
	}
}

func TestMakePNA(t *testing.T) {
	e := echo.New()
	pnaMiddleware := MakePNA()

	testCases := []struct {
		name               string
		method             string
		headers            map[string]string
		expectedStatusCode int
		expectedHeader     string
	}{
		{
			name:               "OPTIONS request with PNA header",
			method:             http.MethodOptions,
			headers:            map[string]string{"Access-Control-Request-Private-Network": "true"},
			expectedStatusCode: http.StatusOK,
			expectedHeader:     "true",
		},
		{
			name:               "OPTIONS request without PNA header",
			method:             http.MethodOptions,
			headers:            map[string]string{},
			expectedStatusCode: http.StatusOK,
			expectedHeader:     "",
		},
		{
			name:               "GET request",
			method:             http.MethodGet,
			headers:            map[string]string{},
			expectedStatusCode: http.StatusOK,
			expectedHeader:     "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := pnaMiddleware(func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			})

			err := handler(c)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatusCode, rec.Code)
			assert.Equal(t, tc.expectedHeader, rec.Header().Get("Access-Control-Allow-Private-Network"))
		})
	}
}
