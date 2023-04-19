// Package data provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/algorand/oapi-codegen DO NOT EDIT.
package data

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	. "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/oapi-codegen/pkg/runtime"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Get a LedgerStateDelta object for a given round
	// (GET /v2/deltas/{round})
	GetLedgerStateDelta(ctx echo.Context, round uint64, params GetLedgerStateDeltaParams) error
	// Removes minimum sync round restriction from the ledger.
	// (DELETE /v2/ledger/sync)
	UnsetSyncRound(ctx echo.Context) error
	// Returns the minimum sync round the ledger is keeping in cache.
	// (GET /v2/ledger/sync)
	GetSyncRound(ctx echo.Context) error
	// Given a round, tells the ledger to keep that round in its cache.
	// (POST /v2/ledger/sync/{round})
	SetSyncRound(ctx echo.Context, round uint64) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// GetLedgerStateDelta converts echo context to params.
func (w *ServerInterfaceWrapper) GetLedgerStateDelta(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "round" -------------
	var round uint64

	err = runtime.BindStyledParameterWithLocation("simple", false, "round", runtime.ParamLocationPath, ctx.Param("round"), &round)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter round: %s", err))
	}

	ctx.Set(Api_keyScopes, []string{""})

	// Parameter object where we will unmarshal all parameters from the context
	var params GetLedgerStateDeltaParams
	// ------------- Optional query parameter "format" -------------

	err = runtime.BindQueryParameter("form", true, false, "format", ctx.QueryParams(), &params.Format)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter format: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetLedgerStateDelta(ctx, round, params)
	return err
}

// UnsetSyncRound converts echo context to params.
func (w *ServerInterfaceWrapper) UnsetSyncRound(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.UnsetSyncRound(ctx)
	return err
}

// GetSyncRound converts echo context to params.
func (w *ServerInterfaceWrapper) GetSyncRound(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetSyncRound(ctx)
	return err
}

// SetSyncRound converts echo context to params.
func (w *ServerInterfaceWrapper) SetSyncRound(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "round" -------------
	var round uint64

	err = runtime.BindStyledParameterWithLocation("simple", false, "round", runtime.ParamLocationPath, ctx.Param("round"), &round)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter round: %s", err))
	}

	ctx.Set(Api_keyScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.SetSyncRound(ctx, round)
	return err
}

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface, m ...echo.MiddlewareFunc) {
	RegisterHandlersWithBaseURL(router, si, "", m...)
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string, m ...echo.MiddlewareFunc) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.GET(baseURL+"/v2/deltas/:round", wrapper.GetLedgerStateDelta, m...)
	router.DELETE(baseURL+"/v2/ledger/sync", wrapper.UnsetSyncRound, m...)
	router.GET(baseURL+"/v2/ledger/sync", wrapper.GetSyncRound, m...)
	router.POST(baseURL+"/v2/ledger/sync/:round", wrapper.SetSyncRound, m...)

}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
	"4er/BwAA//8yQRH0B8oAAA==",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}