// Package private provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package private

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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
	"github.com/oapi-codegen/runtime"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Gets the merged config file.
	// (GET /debug/settings/config)
	GetConfig(ctx echo.Context) error

	// (GET /debug/settings/pprof)
	GetDebugSettingsProf(ctx echo.Context) error

	// (PUT /debug/settings/pprof)
	PutDebugSettingsProf(ctx echo.Context) error
	// Return a list of participation keys
	// (GET /v2/participation)
	GetParticipationKeys(ctx echo.Context) error
	// Add a participation key to the node
	// (POST /v2/participation)
	AddParticipationKey(ctx echo.Context) error
	// Generate and install participation keys to the node.
	// (POST /v2/participation/generate/{address})
	GenerateParticipationKeys(ctx echo.Context, address basics.Address, params GenerateParticipationKeysParams) error
	// Delete a given participation key by ID
	// (DELETE /v2/participation/{participation-id})
	DeleteParticipationKeyByID(ctx echo.Context, participationId string) error
	// Get participation key info given a participation ID
	// (GET /v2/participation/{participation-id})
	GetParticipationKeyByID(ctx echo.Context, participationId string) error
	// Append state proof keys to a participation key
	// (POST /v2/participation/{participation-id})
	AppendKeys(ctx echo.Context, participationId string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// GetConfig converts echo context to params.
func (w *ServerInterfaceWrapper) GetConfig(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GetConfig(ctx)
	return err
}

// GetDebugSettingsProf converts echo context to params.
func (w *ServerInterfaceWrapper) GetDebugSettingsProf(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GetDebugSettingsProf(ctx)
	return err
}

// PutDebugSettingsProf converts echo context to params.
func (w *ServerInterfaceWrapper) PutDebugSettingsProf(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.PutDebugSettingsProf(ctx)
	return err
}

// GetParticipationKeys converts echo context to params.
func (w *ServerInterfaceWrapper) GetParticipationKeys(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GetParticipationKeys(ctx)
	return err
}

// AddParticipationKey converts echo context to params.
func (w *ServerInterfaceWrapper) AddParticipationKey(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.AddParticipationKey(ctx)
	return err
}

// GenerateParticipationKeys converts echo context to params.
func (w *ServerInterfaceWrapper) GenerateParticipationKeys(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "address" -------------
	var address basics.Address

	err = runtime.BindStyledParameterWithOptions("simple", "address", ctx.Param("address"), &address, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter address: %s", err))
	}

	ctx.Set(Api_keyScopes, []string{})

	// Parameter object where we will unmarshal all parameters from the context
	var params GenerateParticipationKeysParams
	// ------------- Optional query parameter "dilution" -------------

	err = runtime.BindQueryParameter("form", true, false, "dilution", ctx.QueryParams(), &params.Dilution)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter dilution: %s", err))
	}

	// ------------- Required query parameter "first" -------------

	err = runtime.BindQueryParameter("form", true, true, "first", ctx.QueryParams(), &params.First)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter first: %s", err))
	}

	// ------------- Required query parameter "last" -------------

	err = runtime.BindQueryParameter("form", true, true, "last", ctx.QueryParams(), &params.Last)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter last: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GenerateParticipationKeys(ctx, address, params)
	return err
}

// DeleteParticipationKeyByID converts echo context to params.
func (w *ServerInterfaceWrapper) DeleteParticipationKeyByID(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "participation-id" -------------
	var participationId string

	err = runtime.BindStyledParameterWithOptions("simple", "participation-id", ctx.Param("participation-id"), &participationId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter participation-id: %s", err))
	}

	ctx.Set(Api_keyScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.DeleteParticipationKeyByID(ctx, participationId)
	return err
}

// GetParticipationKeyByID converts echo context to params.
func (w *ServerInterfaceWrapper) GetParticipationKeyByID(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "participation-id" -------------
	var participationId string

	err = runtime.BindStyledParameterWithOptions("simple", "participation-id", ctx.Param("participation-id"), &participationId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter participation-id: %s", err))
	}

	ctx.Set(Api_keyScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GetParticipationKeyByID(ctx, participationId)
	return err
}

// AppendKeys converts echo context to params.
func (w *ServerInterfaceWrapper) AppendKeys(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "participation-id" -------------
	var participationId string

	err = runtime.BindStyledParameterWithOptions("simple", "participation-id", ctx.Param("participation-id"), &participationId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter participation-id: %s", err))
	}

	ctx.Set(Api_keyScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.AppendKeys(ctx, participationId)
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

	router.GET(baseURL+"/debug/settings/config", wrapper.GetConfig, m...)
	router.GET(baseURL+"/debug/settings/pprof", wrapper.GetDebugSettingsProf, m...)
	router.PUT(baseURL+"/debug/settings/pprof", wrapper.PutDebugSettingsProf, m...)
	router.GET(baseURL+"/v2/participation", wrapper.GetParticipationKeys, m...)
	router.POST(baseURL+"/v2/participation", wrapper.AddParticipationKey, m...)
	router.POST(baseURL+"/v2/participation/generate/:address", wrapper.GenerateParticipationKeys, m...)
	router.DELETE(baseURL+"/v2/participation/:participation-id", wrapper.DeleteParticipationKeyByID, m...)
	router.GET(baseURL+"/v2/participation/:participation-id", wrapper.GetParticipationKeyByID, m...)
	router.POST(baseURL+"/v2/participation/:participation-id", wrapper.AppendKeys, m...)

}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/+x9a3Mbt5LoX0Fxt8qPJSnZsbMnvnVqrxLnoY0Tuywle/dYvgk40yRxNAQmAEYi4+v/",
	"fguNx2BmMOSQou2kNp9scfBoNBqNRj/fjTKxKgUHrtXo2btRSSVdgQaJf9E8l6DwvzmoTLJSM8FHz0Zn",
	"nNAsExXXpKxmBcvINWymo/GIma8l1cvReMTpCkbPwiDjkYTfKiYhHz3TsoLxSGVLWFE7rdYgTd83Z5N/",
	"nE6+ePvu6d/ej8YjvSnNGEpLxhej8Wg9WYiJ+3FGFcvU9MyN/37XV1qWBcuoWcKE5elF1U0Iy4FrNmcg",
	"+xbWHG/b+laMs1W1Gj07DUtiXMMCZM+ayvKc57DuW1T0mSoFunc95uOAlfgxjroGM+jWVTQaZFRny1Iw",
	"rhMrIfiV2M/JJUTdty1iLuSK6nb7iPyQ9h6NH52+/5dAio/GTz9LEyMtFkJSnk/CuF+FccmFbfd+j4b+",
	"axsBXwk+Z4tKgiK3S9BLkEQvgUhQpeAKiJj9EzJNmCL/efHyRyIk+QGUogt4RbNrAjwTOeRTcj4nXGhS",
	"SnHDcsjHJIc5rQqtiBbYM9DHbxXITY1dB1eMSeCGFt6M/qkEH41HK7UoaXY9ettG0/v341HBViyxqh/o",
	"2lAU4dVqBpKIuVmQB0eCriTvA8iOGMOzlSQrxvXnT9p0WP+6ousueJey4hnVkEcAakm5oplpgVDmTJUF",
	"3SBqV3T999OxA1wRWhSkBJ4zviB6zVXfUszcR1sIh3UC0ZdLIOYLKekCIjxPyU8KkJLwqxbXwAN1kNkG",
	"P5USbpioVOjUsw6cOrGQiA6kqHiKURH84NDcw6Ns32MyqNc44vvt3xRbuE9tqC/Y4nJTApmzwtyX5J+V",
	"0oGAK4XbvgSiSsgM782JGcYgX7EFp7qS8OyKPzR/kQm50JTnVObml5X96Yeq0OyCLcxPhf3phViw7IIt",
	"enYgwJo6pwq7rew/Zrz0UdXr5F3yQojrqowXlMVnwdDK+fM+yrBj9pNGmkGeBbkB98eNdbk+f97HUrf3",
	"0OuwkT1A9uKupKbhNWwkGGhpNsd/1nMkLTqXv4+seGF663KeQq0hf8euUaA6s/LTWS1EvHafzddMcA32",
	"KozEjBNkts/exZKTFCVIzeygtCwnhchoMVGaahzpXyXMR89G/3JSC3ontrs6iSZ/YXpdYCdzGUswjG9C",
	"y3KPMV4Z4RFFrZ6DbviQPepzIcntkmVLopdMEcbtJqLcZThNATeU6+lor5P8PuYObxwQ9VbYS9JuRYsB",
	"9e4FsQ1noJD2ndB7TzUkRcQ4QYwTynOyKMQs/HD/rCxr5OL3s7K0qBoTNifA8D6HNVNaPUDM0PqQxfOc",
	"P5+Sb+Oxb1lREMGLDZmBu3cgN2Navu34uBPADWJxDfWI9xTBnRZyanbNo8HIZccgRpQql6IwV+BOMjKN",
	"v3NtYwo0vw/q/Kenvhjt/XSHEr1DKlKT/aV+uJH7LaLq0hT2MNR01u57GEWZUbbQkjqvEXxsusJfmIaV",
	"2kkkEUQRobntoVLSjZegJigJdSnoJwWWeEq6YByhHRuBnJMVvbb7IRDvhhBABUnbkpkVr26ZXtYiV0D9",
	"tPO++HMTcmrPidlwyoxsTAqmtBGGcDMVWUKBAicNioWYig4imgG0sGURAeZbSUtL5u6LleMYJzS8vyys",
	"d7zJB16ySZhjtUWNd4TqYGa+k+EmIbEKhyYMXxYiu/6OquURDv/Mj9U9FjgNWQLNQZIlVcvEmWrRdj3a",
	"EPo2DZFmySyaahqW+EIs1BGWWIh9uFpZfkWLwkzd5Wat1eLAgw5yURDTmMCKafMAZhxPwILdALesZ0q+",
	"ptnSCBMko0UxrvUSopwUcAMFEZIwzkGOiV5SXR9+HNk/lPAcKTB8UAOJVuN0GlNyuQQJcyHxoSqBrChe",
	"TivzPCqLZp/AXBVdQUt2wstSVNrAGL1czp/71cENcORJYWgEP6wRH/zx4FMzt/uEM3NhF0cloKKF8ayo",
	"8hp/gV80gDat66uW11MImaOih2rzG5MkE9IOYS9/N7n5D1BZd7bUeb+UMHFDSHoDUtHCrK61qAeBfI91",
	"OneczJxqGp1MR4XpF53lHNgPhUKQCe3GS/wPLYj5bAQcQ0k19TCUU1CmCfuBd7ZBlZ3JNDB8Swuysnoz",
	"UtLsei8ov6onT7OZQSfva6uqc1voFhF26HLNcnWsbcLB+vaqeUKszsezo46YspXpRHMNQcClKIllHy0Q",
	"LKfA0SxCxPro19qXYp2C6Uux7lxpYg1H2QkzzmBm/6VYP3eQCbkb8zj2EKSbBXK6AoW3W8MMYmapVdVn",
	"MyEPkyY6polaAU+oGTUSpsYtJGHTqpy4s5lQj9sGrYFIUC9tFwLaw6cw1sDChaYfAAvKjHoMLDQHOjYW",
	"xKpkBRyB9JdJIW5GFXz2mFx8d/b00eNfHj/93JBkKcVC0hWZbTQoct/p+YjSmwIeJB9OKF2kR//8iTeI",
	"NMdNjaNEJTNY0bI7lDW02IexbUZMuy7WmmjGVQcAB3FEMFebRTt5bfu9H4+ew6xaXIDW5hH8Sor50blh",
	"Z4YUdNjoVSmNYKGaRiknLZ3kpskJrLWkJyW2BJ5b05tZB1PmDbiaHYWo+jY+r2fJicNoDjsPxb7bVE+z",
	"ibdKbmR1DM0HSClk8goupdAiE8XEyHlMJHQXr1wL4lr47Srbv1toyS1VxMyNBrCK5z0qCr3mw+8vO/Tl",
	"mte42XqD2fUmVufmHbIvTeTXr5AS5ESvOUHqbGhO5lKsCCU5dkRZ41vQVv5iK7jQdFW+nM+PoyMVOFBC",
	"xcNWoMxMxLYw0o+CTPBc7dTmeGtgC5luqiE4a2PL27J0P1QOTRcbnqEa6RhnuV/75Ux9RG14FqnCDIwF",
	"5IsGrX5QlVcfpiwU91QCUoOpF/gZLQLPodD0GyEva3H3Wymq8ujsvD3n0OVQtxhnc8hNX69RZnxRQENS",
	"XxjYp6k1fpIFfRWUDnYNCD0S6wu2WOrofflKig9whyZnSQGKH6xyqTB9uiqmH0VumI+u1BFEz3qwmiMa",
	"uo35IJ2JShNKuMgBN79SaaG0x2vHHNSskhK4juVc1GcwRWZgqCujlVltVRItUvdL3XFCM3tCJ4ga1ePm",
	"EFw1bCs73ZLeAKGFBJpvyAyAEzEzi669HHCRVJHSyM5OrHMi8VB+2wC2lCIDpSCfOH32Tnh9O3v/6C3I",
	"w9XgKsIsRAkyp/LDrOD6Zifw17CZ3NCiMuL59z+rB3+URWihabFjC7BNaiPa6rvuUu4A0zYibkMUk7LV",
	"FtqTYERsw3QK0NCH7Ltjr3f722B2iOADIfAGJHrUfNCj5Sf5AEQZ4P/AB+uDLKEqJ0YM7FU/GMnV7Den",
	"XHjZcMcMYYKCKj3ZdaWYRg29iVlqxMVTtwgO3CNPvqBKoxhIGM9Rf2uvQpzHypZmitGeTmU4Ze9rzEz6",
	"s3+IdafNzPXOVaXCq0xVZSmkhjy1PLRZ9871I6zDXGIejR2eflqQSsGukfsQGI3v8OgUAfgH1cFC7Wze",
	"3cWh14ERXzb7YrkBX42jbTBe+FYR4mOn2h4Ymar3wJIbUy16mwlRAEWVqdKiLA2H0pOKh359GLywrc/0",
	"T3XbLklaM5CVVHIBCk1Mrr2D/NYiXaGta0kVcXB4/wRUeFkXuS7M5lhPFOMZTLadF3wEm1bxwTnouFfl",
	"QtIcJjkUdJPwtrCfif28J2H4sZFAav2B0DCZoTUxTSP1mfD+pofNKnAqlRK8CX4hmTnn5hlVk5rrffik",
	"OeC0Kb7piPVemAXBSNKBHw+RZekpMSLe/TdCG7JyRIercbfSHdfSg70w6wdBII47qRUB7dn/G5SbOwhg",
	"R51/A6pv4fXUx1p2j/of7/bGhdm6ylq3TfKK6OXLOxhjHw/qsUW8olKzjJX4XP0eNkd/vbcnSPpKkBw0",
	"ZQXkJPpgX/Jl3J9YN+T2mIe95gepW7vgd/StieV4z6wm8NewQbXJKxvREGmrjqGOSIxqLlzKCQLqvebN",
	"iyduAmua6WJjBFu9hA25BQlEVTPrtdI1oWlRTuIB0jFT/TM6g3zSHL7VQ+ACh4qWl/I8tK+t7fBdtp5c",
	"DXS4V1YpRJHQf7ZPfAcZSQgGuQuRUphdZ7QoNkSHsBlPSQ0g3QWB3hhBnrmnGmjGFZD/FhXJKMcXbqUh",
	"CGlCouSDwrKZwYibYU7nqlpjCApYgX3N45eHD9sLf/jQ7TlTZA631uWGY8M2Oh4+RFXcK6F043AdQdtt",
	"jtt54tJBW6W5ZN2rrc1Tdju5uZGH7OSr1uDBwGnOlFKOcM3y78wAWidzPWTtMY0Mc/DDcQeZ75ouYZ11",
	"475fsFVVUH0MQyXc0GIibkBKlsNOTu4mZoJ/fUOLl6Hb+/EI1pAZGs1gkmGU4MCx4NL0sYGFZhzGmTnA",
	"NnBkKEBwbntd2E47Xtq13zJbrSBnVEOxIaWEDGyUnJFSVVjqlNiQiWxJ+QJfQFJUC+fqbMdBhl8pqwmT",
	"Fe8Msa8optd8giYMlQxTQ7Olj7Y0QhhQ87Jt2z/sY+2WBlDsZTTo0o62p20PSppMx6Peh7/B90398Ld4",
	"a4aMHmpMbMiHEdJqaAZazxCfRlbqIjHeRnP4DDF8GCtNPXQKyu7EkVN4/bHPL/yiKsticwQhyQ5EJJQS",
	"FF5psRpQ2a9iTn5gmRRnxUKEO09tlIZV13hju/7Sc1xfH/ICFrxgHCYrwSHxpH+JX3/Aj4PVjvYa7hkR",
	"BaK9Bmw/fBpIaC2gOfkQkr7rJiHJtM9+29KpvhHyWFZ2O+DgN8UAy/VOtw435aH2dVoUCZO0VT90uIga",
	"B6dwJglVSmQMBcXzXI2d97m1Ylu39hb6X4XQqCMc4Pa4LdtrFIZlFflQlISSrGCo5hdcaVll+opT1PRF",
	"S004C3rlQL9a+CvfJK2HTqiJ3VBXnKKjaND/JR2D5pDQQ30D4LXDqlosQOnWA2sOcMVdK8ZJxZnGuVbm",
	"uEzseSlBosfe1LZc0Q2ZG5rQgvwOUpBZpZtPjlWlNFGaFYUzBJtpiJhfcapJAVRp8gPjl2sczvuR+CPL",
	"Qd8KeR2wMB3OuBbAQTE1SXs6fmu/YlCJw8nSBZhgrIX97D2e69wQI7P2RtKK/3v/P569OZv8g05+P518",
	"8W8nb989ef/gYefHx+///vf/1/zps/d/f/Af/5raPg97KhjcQX7+3L3Rz5/jQyyKE2nD/kcwyKwYnySJ",
	"MnYoatEiuY/5MhzBPWjq/fQSrrhec0N4N7RgueFFRyOf9jXVOdD2iLWorLFxLTWeR8Cez6E7sCqS4FQt",
	"/vpB5Ln2BFsdbuItb8UYOM6ojg6gGzgFV3vOlFvtvW+/viQnjhDUPSQWN3SUWiDxgnERjA0vH7NLcWDX",
	"Fb/iz2GO70HBn13xnGp6Yk/TSaVAfkkLyjOYLgR55oMin1NNr3jnGupNIBUFNUcZpFKcgq7Sa7m6ekOL",
	"hbi6etvxQ+jKVm6qmIu6c9ZVk/kpJ0ZuEJWeuCQuEwm3VKZsIT7Fh4uGxt5b4bAyiaisEssniXHjT4dC",
	"WZaqneyhi6KyLAyKIlJVLl+B2VaitAiBY4aZu9hbQwM/CudUIumtf/JWChT5dUXLN4zrt2RyVZ2efoYh",
	"eHWKg18dDzR0uylh8MO3NxlF+72LC7dyOTqVT0q6SNlMrq7eaKAlUggKHCt8aRYFwW6N8EAfCYBD1QsI",
	"sch7bImFbO+4Xlzuhe3l03qlF4WfcFObsdN32sEoKv7gDdwRWU8rvZwYjpBclTLHwO+VTzBAF+bK8R4E",
	"ii3wAaCWojJLBpItIbt2ma1gVerNuNHdO7q4u9gzHKZQZ+SCA+fM4C+j3AxYlTl1ggzlm3aKG2WDIXDQ",
	"13ANm0thu08HZgeLstFFKVZU39FF2o3uWkO+8UF2Y7Q33/ld+RhRl44E4y49WTwLdOH79B9tKwAc4Vin",
	"iKKR56MPEVQmEGGJvwcFByzUjHcn0k8tj/EMuGY3MIGCLdisSLDp/+raNTyshiolZMBufFRvGFARNifm",
	"dTSz17F7MUnKF2AudXMRC0ULdNqfJg39KB0ugUo9A6q36mt5nGbCQ4cC+S0GTaPSZGyWAGuz30yjEoTD",
	"rXng4dvbtnGOxNOD3KnsmiA/EFTfvQ6Snh7yiHAIT+Sz8/d92JPwXnD+aTF1Isj2+8rgcCHFrdlNA6Dw",
	"qRsxwUt0T1WKLmDoddQwFQ1MidGwAOEgu6SfpLwj5m2xpiNjDFyE7T4xeElyBzBfDHtAM0DLxdHPbU2I",
	"zqrwkhcbj9RZgQJ1cBC1pENlw87GF/sBm2ZjIHktrHrAmliLj/6SKn/083HE0Q+UFj9NKplt+fPOI+87",
	"qrvZ8fw13WbtY6vPmQER3PTwWfR86jyfL2803iv33XjkQhxSeyc4StE5FLCwOLGNPZ3V+Znq3TRwvJzP",
	"kelNUo58kTIykkzcHGAeYg8JsRpzMniE1CmIwEbLOg5MfhTxYeeLfYDkLr8U9WPj3RX9DelgQeuNb6Rk",
	"UZpbn/VYrTLPUlx6i1rkabk44zCE8TExnPSGFoaTusDTepBOrjZ8+7Qysznfjgd9b6KBB82tEaWTvVZp",
	"5ZlD1hcL3n4Z6VfBXmuYifXERkYnn1az9cyciWS8AsZppw6vzZx3T5GZWKNPEd5w1sF9b+j6IfOARW4g",
	"a6aQyrFfn9howdsPkO2CfIqaFZKe06sFsuuTZA8Dpkec7iO7+1EKvSOB1FJg1mnAnUZnp56lKW11JZH6",
	"uh2H7LAhTC3FavoOZ3InezDaVZ42c919V6c77E+O5s/qR0ny11XK3SUvo+1c2lyL+6RlbJNDA4gtWH3V",
	"FmKTaG06LjXxGmEtxZIMo+8au7poU1AAagImDbl6cp0yS19dvVGAMsOF7xbpOXH3KN88iLzhJCyY0lAb",
	"F7yTy8e3/aA60Ty2xLx/dbqUc7O+10IEQcOaY7FjY5kffQXouj5nUukJWmaSSzCNvlGoSfvGNE0Lwk1/",
	"O6asqWdvORghuobNJGdFlSZlB9L3zw1EP4abS1UzvCgZt95GM0yFn3TQ3cM2ifBYx+6tCHphEfSCfgz8",
	"DDtYpqmBSRrKa07/JzliLV64jbMkaDlFTN0N7UXpFl4bxdJ3GW0kREduF9NtNp/Oucz92Du9sXxEf58Q",
	"YUdKriXKiJgOIBSLBeQ+05sLCrVZr1w+vULwRZ1L0Py+JX3glNgsfpiEb0v+PueeDn3O6Y1yIlgVIwl9",
	"/JhByOvoOsw9iJMsgNvMLaP9640UScTFjvHYItKMflze3nGbT7oOX7bchWufXruHYbNxewqguXtWKfDr",
	"235ou9vlUDfuczpupIjdfsBwQKQ4plUkwHSIpodz07Jk+bpl+LOjTg8giYHiXjcTfAtnyJbcYDvw03Qs",
	"3lGr5565HbG9M3ac4DP/xDwyrT+z88g1Z4NmLttAXkm0JjW8hbv59MNDc+Dav//5QgtJF+AsghML0p2G",
	"wOXsg4YoJb0imlkH6ZzN5xBbwtQhVpwGcB17Rz6AsHtIsGsuC2/LrfTZJbIdtFWvYDdC0/SUoJQ+n4vL",
	"rj3SPzwi3Vq4bKKNO8ComEwo8D1sJj/TojIvISZV7ZvqDITNa30PmrhZfQ8bHHmny6cBbMeuoCruNSCF",
	"pqwr4ZOKsoTfU43qC/gGbmzhHjt1lt6lI22NK6XRfzTqG6pRT6K5lA93bGoXGQPpkL26SHudmLMFzW1p",
	"E/quLWL5btkneoLEUzH03jjkkguZNnZ6lwEtPOHjYkfvx6O7+Xuk7kk34o6deBWu5uQuoDemtf83nL72",
	"3BBallLc0GLi/GT6hA4pbpzQgc29W81Hfl+lT8Xl12cvXjnw349HWQFUToKqo3dV2K7806zKluDYfg3Z",
	"dOxOt2tVYdHmh5TZsSfNLaZeb2nTOrVuar+p6KA6z5p52lN8J990Ll52iVtcvaAMnl61Rdo6ejWdu+gN",
	"ZYU3/Hpoh2rZ7XKHVVdK8ol4gDs7iUXef3ceqzdO4OrqzY3HbG1PsY5SISV+wpdOHejp3OE16bNa0/oO",
	"DonrfImZTNPvLu7ynCJjdA5n9Ohy4DdCNi4qF9WYdFj7cAKieUxYPKaN8pfOCt8RC6fEipC/Ln41vOHh",
	"w/jgP3w4Jr8W7kMEIP4+c7/jO+rhw6RhOKnqMywLNXmcruBBiIvo3YiPq4bgcDtMXDi7WQUZWfSTYaBQ",
	"63nm0X3rsHcrmcNn7n7JoQDz03SIqiLedIvuGJghJ+iiLyoxOD+vbDlPRQRvx+BjlKwhLbx6XAUPa2fv",
	"HiFerdDuPFEFy9JOP3ymDEvi1qXXNCbYeLAN2cxRsR6/cl6xaHTTTB1k8mwtJJo1iXCVzARc43cmHAuo",
	"OPutgqisL97ErcvZP4Vw1I6AndYvuoHbVYNHhxT8vbuJ0GvVtimMtppcnwczoEdEqs7UnvEO8Ywd5r8l",
	"VsFRlL8+MbBt6VyHd1LW1nfe9iLQzgzs2aezuPY/kFw5TLuZz4fsNFOTuRS/Q1p2QCNhInWHt24zVMD/",
	"Djzlo9pmZMFzoC5YXc++i0CG6xb6SOXOugS/6FA175ArPM0n9tvoPZUG0X73qw1UOr2424S+h2rseNIM",
	"pOlhZnhgI7dwrOXj3d0otyfU5rVoRJ6lz3kcKHpix6/PuYO5E1xb0NsZTRU6Mu9FA1O0/Q3HPC2I7+w3",
	"SIXUDHZ2EsUyhLbMJvsrQdbWo26q5APffnbawa+++pGHFBc/78bWV6VQIjFMxW8pRz9C7Gc5oOutwPph",
	"mF63QmKCT5X2IcwhY6ukMvzq6k2edT2/crZgtqR4pYDQuXZ5Ht1Atqi8pSJXzTvkInGoOZ+T03F9Zv1u",
	"5OyGKTYrAFs8si1mVOEFHXwiQhezPOB6qbD54wHNlxXPJeR6qSxilSDhfY6iZ/CEnYG+BeDkFNs9+oLc",
	"R4dhxW7gQfqCccLa6NmjL8bbKmcjxrFI/DYmnyOX94EMacpGr2o7hmGrbtR0ZMJcAvwO/ffJlvNluw45",
	"XdjSXUG7T9eKcmoQkoJptQMm2xf3F105Wnjh1joDSkuxIUyn5wdNDcfqiSY3DNGCQTKxWjG9cp6iSqwM",
	"hdVlyO2kfjisr+fLoHm4/Ed0wS4Tb/xP8Nyiq54IR/Sq/xHt7TFax4TajK0Fq+MvfIVacu4zU2NduFAO",
	"zuLGzGWWjvIqhmPMSSkZ16g1qvR88jfzfJc0Mwxx2gfuZPb5k0R9tWYJIr4f4B8d7xIUyJs06mUP2Xsp",
	"x/Ul97ngk5XhKPmDOqVDdCp7fcXT/r19bsc9Q99ZujbjTnoJsGoQII24+Z1IkW8Z8I7EGdazF4XuvbKP",
	"TquVTBMMrcwO/fT6hZNEVkKmKl3UDMBJJRK0ZHCD8aXpTTJj3nEvZDFoF+4C/af1bvNiaSS6+dOdfCxE",
	"VuXEOy2kVTKS/s8/1Pnx0bht43Zb2kshE3pap3H8yG6p++kL2zZ06w6I33owNxhtOEoXKz3hHjaeI/T5",
	"FP5ebZDsnjdUpY9+JdK841HWf/gQgX74cOxE5V8fNz9b9v7w4XCX2bS+0PyaQM1hd007e6Xpm9rqL0VC",
	"e+ereAa/MZeqJKFhTd5l5kqduTHGpFkq8ePLHceJV9zbDTl9gDxq8HMbN5+Yv+Jm1hEw/fyhWT02ST55",
	"+B7FUFDypVgPJaLWteXp6Q+Aoh6UDNQK4ko61XGTnhI73XwisjWjzqAQ5qUaF8Aa7LXyJ9oFg5rxlr2o",
	"WJH/XFuhWzeTpDxbJp3KZ6bjL/YZEDWINBjZknIORbK3fS3/4l/ViXf/P0XPsCvG05/ahZgt7C1Ia7Ca",
	"QPgp/fgGV0wXZoIYRc2EXCHFSbEQOcF56solNWvsVjRPVZJNxPjjsKtKO69kTJ7gCorMWYFutGl7OLac",
	"SKp7uCqW/fclrsw4WIVfWbWEHR0koWyF17aiq7IAPIQ3IOkCuwoOre6YsQ1HjsqSEFWaT9gSk78IoivJ",
	"iZjPo2UA10xCsRmTkiplBzk1y4I1zj169uj09HSYkRHxNWDtFq9+4S/rxT06wSb2i6v8ZQsm7AX+IdC/",
	"r6lun83vEpcrv/pbBUqnWCx+sAHZaCE297otvRrKBE/Jt5ifzBB6o0QAKkV9huVmTtCqLATNx5gU+vLr",
	"sxfEzmr7SEDUYenXBWoAm0ckaeQZniPV51/ryV01fJztqXPMqpWehKKsqUyKpkVdS5a1vJ9QNxhjZ0qe",
	"W7VscOyxkxBMLS5XkEc1YK0aAInD/Edrmi1R3zkdbVUp91QDGl7C2HPA2lwUxb2GglnIwc0yXBVjW8R4",
	"TIRegrxlCjDvBNxAM2FjyHbqFPI+gWNztbLi3BLOdA/pNZTH2ncXPHBW9PX+FUnIWvtwZ9tfnckDi5zv",
	"W+z5Anul43ZalaNbfg+2ZMbaF92Ykh+csSOjXHCWYbGJlAiOqRiHmVUH1OVI2zvVyJ3lxDFM1qsOAeoO",
	"i70VrD3LdIjrOjVEX81+W8Kxf2pYuyKAC9DK8UDIx758vDPQMa7AFUAz9BVzVCETrl/JsJjgQnJEl/Tx",
	"CLOp9ehavzHffnS6ecwZc8046twcUt1L0BrYCsXQzs4J02QhQLnVNuPC1BvTZ3q55gjC2+kLsWDZBVvg",
	"GNYV0SDFegF3hzrzPsHOB9e0/cq0dbULws8Nlzo7qV/32yQLUWH/UzXXe9Gf8v3yjjQRcsP48WhbiHGr",
	"qz/ey4YM4QY9/6DE+7xDNqF8fXOUr82T1dIbtiA2cjeZNpjxBBgvGPcG33QerCx5l+DG4Gnu6acySbV9",
	"dAzieJdAi55wGAyqtx4Ddx2qXYnBoATX6Ofo38a68n4PWwkN6tcF5RviD4Wh7kgo+YoWwRk+UUcfpTMn",
	"jFln4VZl/RRbMWx94kNzG+jaGQgaumM1lH3vqb5so7MqX4Ce0DxP5Z37Er8S/OoDCmENWRWKgIU402a6",
	"9i61uYkywVW12jKXb3DH6XKmqFKwmhUJ19vn4SPkYYcxEdVsg/+mKmD174xzet87+tt7uOf71SjoRrOn",
	"pGdD0xPFFpPhmMA75e7oqKc+jNDr/keldB/4/YeI625xuXiPUvzta3NxxGm6Oz7+9moJWbTRn17gd58P",
	"LGRybXIlvMo6dd7QIwM3L7FlLeB9wyTgN7ToybgQW23s/WotGX15F7LetCJUu+x1mpKaJwxRYfTn/7Ie",
	"2C3LUNe82edjbV2sP6TxxOFjK9L7LY3fN+yK1uutZii99sTDTH41Eexr83OlGLr6UloUIhvMGdwwZ6ZT",
	"f6pesVq5zPcJr7yblcjjsxB7cwGkGZt1WE6EVuDDNvkNn1bJL/I2PVpDPxKIZmjWMkSjW8LYBmZ68Dww",
	"dup4okhl6zBLvmEFFof6z4uXP476NzLage6WutTZSRV238aESLU2eSxEAx9beIDgRVr/rXpU6pgbKn0a",
	"XHXi5IdvrIJwCEg2T9I+rV8MHbxDAAthq0Kl6mZ0s9OM6u3wyI+ood5ey1Fi6khRRbvaUuLtY5WedRMS",
	"CpEOKkzakJGGFHdK1RFyLwWvgbUXjctHZ4srdeoydRjo8yHCYQcf78ej83wv8SlVi2pkR0kx2BdssdRf",
	"FiK7/g5oDtLWE0k9J201kRWYZ6hashLfP6VQrK4HXJjBXCLvJQ43HRqac7kElxXGJwnojOUdqG8g01gf",
	"unYDlQDD/RzK9BINBN6giE0+gSuIBMih1MutwpJ17i71si4bCi7yjCkyA2e6uAE+JmwK03awWl4nhSIF",
	"0LlXwkoh9IC6uiFsCdEYA52ir06N5u1iYCfnW5TS0JbSnQ4vwnIWYgJsoOUtVXXmqFYahcHh2vM5ZJjw",
	"fmv6vf9aAo/ysY296g5hmUfZ+FgIF8SSDUfVaNewbkuEtxXUqCbVh4S0LyHGNWzuKdKgoWRF4BBhe0gG",
	"eESOteP6ogJ9pg3nGMlUoCdEkPeDdwn46xpLhxQBiLJTHgiGp3FzPdUZKw+Dxks0B4Bhuk7vVLS/ToeH",
	"gmlfdr9udfX+l/JzLGavnFMpDenmY30SOe+WY7516eox0WKwFvrE9aD8bz5Bq52lYNeuQg0izNpmb6nM",
	"fYujpMmz9yZLAz0PM7M6MKrr5bOvX46NUMwKYQSgSV9gaDNSKbjw3lPW17pOWoZQz0FKyINNsBAKJlr4",
	"MKs9kn+68Mkt2LNe5gfhreXRv0fIsF1Rbw2F13UhCSwHSbFmAnXO5zFWiIQVNdDLqLhDWg26a4e+st99",
	"ThFf3m+7erUP7+Fc7K6Q7UPvmOpgPj5dc+KEg725VyMRyQGaWcY5yIk34rZLO/BmmkzMq5xXmRVV4rMZ",
	"tNeD045t4WZJpWbWXWXrCRVl5biGzYlV+/iq437HY6CtDGlBjxJKt4jiqLpqlYJ7cRTwPm36zlKIYtJj",
	"GTzv1qNoH4Zrll0DJmYNkSlGCr7XPDZmEnIfDVLBZ+R2ufHVFsoSOOQPpoSccRsd6N1HmhVIW5Pze3rb",
	"/GucNa9shRmngZ5e8XSYFVZ6kXfkfn6YLTyvjzcpMPzyjvPbQQ6YXa95n4/cLZaEadYJng5Vb3T9O1oi",
	"VER+FoqUAHVhDcFfIUtIvKMIZmeJ0gihfwAlzoBMVCFSXviHZJAxQ6UxFU+GAGngA56rNRRu8CQCnJPd",
	"jqys7rPPOyrmRELtm3FoAlaX09QycdWnGmnPHGZpcsa5kBDPiH6mNlFziGzDPMf4nxnTksrNIWlSm6hK",
	"qaF6sbzTWzI4StYLqZ0luzgsCnE7QbY2CdWVUuoA0041r21fp7TuZ476DCK3S6qciLghS5qTTEgJWdwj",
	"HeJtoVoJCZNCoBdmyrFjrs0jYYVxnZwUYkFEmYkcbCG0NAX1zVVxTlH2gsiVLYkCSzuYMsD2ieh44JTm",
	"9rXm2QnKazsLbfjNvzR9bPqKOv2dXfTEugj0xBeAcunuHIZs4y68SDg2I1NbKZsWkedsjXQDMnXk50TL",
	"CsbEtWhX4XcHn0ogK6aUBSXQ0i0rCswewdaRQ0PwB0qjtkd2Pkc/6BuGDm/NTCJWpC7N7RjSr8Q84CLO",
	"yEb0UopqsYzqAwQ4/dNdVu5hH4/yk6rQJxFDRM0UT8hKKO2exXakesm1C+j9THAtRVE0FXlWzl84o+8P",
	"dH2WZfqFENczml0/wEc4FzqsNB/7lApt3916JtnKwTjspaDXfILkoXanWbft0KvV0fNg3tnifh3Dwy5N",
	"fgTm293Mdbdd46y7sPa6mnw2/RY644RqsWJZ+rj9ubxfe31WU9wrmWnRViG2WWiwGfKB+B4L7kzIPbto",
	"Bk6TZVTPiOMRzq0DOZH5L4rx7XHJHBwP6rlDu3zHCViTrFcMbAGAkNpECLqStnRxLKQFhiMWNnEKOqW0",
	"AR144aDv391gMyMcHSgNdwKq440cALxvNRhjmxHTejbPxNp/f1CnzDwI+PfbqbzBPPqcKi9q0pLWrdIn",
	"surhCOkCBFs9EC8xCcZsqB9iKEU/8PKPAOj3TGzAMMg/cV8w5pQVkE9SVYrPgw5sHD3XXYxlNLqv52g5",
	"eUYrXwnYjF1JcImVrPQvm+bEkhpSEqF5VyPOc1iDjdH6HaSwdXzHkTkLClvmt6VREOWkgBtoOGy6bE8V",
	"SqHsBnxfFTqTHKBEi29b0ZbyRIyrBLa0L27tk8iXbQh2k+oYi1i7U2SHriWpGVrziT0mauhRMhDdsLyi",
	"DfypfUWOpi7RHOUEqjrPh4l/Yg6d5ic7wms/wJnvnxJlPCbeDuNDe7OgNOq2MaCdnsmV6jv1PO2YHKcy",
	"C4YinC0Pdm1L4jXfUCW95f1azS7J1y+xgfvEBI8Q+/UaMpRq3FMIcvcY6rGcuBxISO0cILcPBtMloc1f",
	"AidcRDWPb6kKr5g6q6v/wU6MjRh3D+0DbPS1//Ddd5bgYES1ki2mS5QGsr6bjv+TnMStB7F3vBSNKHCh",
	"vFtUY5663bMDG4iqyAk3+2lkf6wR7G4xx8XHZFb5gYpC3NoixvET9Tl4e66lPm9icmI5C9ey95Meu4TD",
	"bS0IiyJEVnRDhMR/zIP0t4oWbL5BPmPB992IWlJDQs6AbL0onN+1mXi7eDX2gHlFjPBT2XWzoWNGw23M",
	"KBHQ5iL3ZdsEWdFriLcBHUQs/8y0YZyqmqFSw1zZre3sYsEt3qdnWtE8VgJgotlNgzv4hOem9/+qw1bj",
	"qXz+x7KgmS9Z7YrPNfkMVrX3xKWXsNoe5tzla54EQqX8mmilT5ORH6BN3ZN1pWJ++opjNcDulADv1AW7",
	"0zIGKoVbNY62BIgPWsqxd+E4MZydJcWlfnctLq58/HF2J5khum8ZQ8D/A+1Kw72iE9mWrqAer8cWS/8I",
	"u9BIxJOA1arBZ2I9kTBXuxxprB58JtY1wCrobhnPJFBl/Y7OX7pna50AmXHzjLZeu8GsGkbJYc54zWoZ",
	"LyudeAVhHmS+iRAWWxMQrT22uT4Zw4iiN7R4eQNSsrxv48zpsaWB4yI93oLi+iYUIOFG7g7AVP0CxHjq",
	"Wj8fNzPXvy0waH1nlaY8pzKPmzNOMpBGaiC3dKMON1UFq8MuYxWNZKFmtpDIbIWkbQEpNs7afEdDUgCQ",
	"HtGiNMAShE7aCSuQVQxp0WP46cLwp7AEreh6UogFRv32HAiX5xpNh/YBKTgq0a10N2zdfh7Ffoft02Ap",
	"EseItMBZh0yx/dy/xK3ER+hPnOmtJ99qONth2NbT2R5Mj1S+qMMzLLF0z2Mqct4lZoqj572o6tOUeNqD",
	"aBOTLtEdrXrPLqJ/hUu7EKvQhxerbLpwpOLzrV5hgvoGtSUAA1QdV0Az5yHWVcR1FBUWKWOX3WBPPZ3V",
	"7vt7qQc8VKQod9ab0wYHHTPOPhU+t+czmJSinGRDfFtttaLcGRkcpE0Ye+gjMiH0rDv43ahQv6uRE61R",
	"yGvfIqe9hcR22crKbJvKoE/J1MPRmwYMMUdehkfYqtYw1iqoYsb+ce6N3U0lWmAShBIJWSVRyXxLN7sL",
	"P/Zkn7/47uzpo8e/PH76OTENSM4WoOqaBq3CibVrIuNtrdHHdUbsLE+nN8FnC7GI89ZLH/YWNsWdNctt",
	"VZ2MuFM2ch/tdOICSAXndkvkHbRXOE4dFvHH2q7UIo++YykUfPg9k6Io0jVlglyVML+kdisywJgXSAlS",
	"MaUNI2zaT5munbLVEpWLmDX8xuaGEjwDr312VMB0jy9XaiF9Pr3IzzAXg7M5EViXheNV1k60bV3unWb1",
	"eyg0orvNDEgpSifaszlJQYQxW7KCoFd3alPUp0duuoHZWofdFCE65/c06Z1x9xIWc7Kd2zdLces0pzeb",
	"mBAv/KE8gDT7rBv9eUYO4SS1YeAPwz8SiVOOxjXCcj8Er0i+D7ZEhZ91vCZC0pBBoHUTZCTIAwHoiYdu",
	"BK1GQXZRbnJpbQxojfDm57b48UNtlt4ZmYKQ+A47wItjmet2IZjCgfOJE3v/EJASLeVtHyU0lr8rPNqz",
	"3nCRRFvklCZag7JsSXTFwiggXn0V4sx7XiWdcHQphCbmZVoUiTB2q8fBMxUTjnkSyBtafHyu8Q2TSp8h",
	"PiB/3R+4FYctx0i2qFRHT8j5gg4CKwpR/ihQ8VcYW/9fYHY2eTu6WZzhv3MHokqIFtbbex4s4MDJLY5p",
	"HbsefU5mrtxPKSFjqu1QcOtFmhBvC5LNnX8trHU79vfOZYJ+FvoOx2Hu/YHIj5GRLXgOOJjro/6JmVMP",
	"B0ielhSpdgglgb8Ur4uLqu+4du5YGuawVE5R4sY9Uzl1y8UPXR6uAy+vSkF3nYNv/QZuExd+vbahucoG",
	"V5i5unqjZ0MSiqWrwZjumOPsKGVh7l4U5qMkOLOodGM4SJKEVYvcu7LXtPwlozwNzV004n5PAfmlRb8Z",
	"DR8F84rb8UIBVIwV92xdzMfBi0Fw0+0ZueIPiVpS/7Zwfz5++vloPAJerczi6++j8ch9fZt6qeXrZFxp",
	"nUin4yPqqgncU6Skm6E15Prz5iSRW6cJ+vjyjNJsln7QfWc2DF+tLvrgnCOfR95ir0+XPOd/bvafvTOI",
	"hbNiibFODBT2YVeOoJ/7EuLbpO89dT5afLdixU73uEYJlvfj0cKmJ8O6JL+4KnUfd889BD2ZAt3S75IA",
	"zCImsdbG5NFUUTq3AaVYXLdEbQyMuc4qyfTmwuDfK9zZL9epNFDfhsRMLttXsL07qVeLa+Deu6xO41Qp",
	"L1d/K2iBcqd1CeBG2hTFlHxta4O4C/Hv92b/Dp/97Ul++tmjf5/97fTpaQZPnn5xekq/eEIfffHZI3j8",
	"t6dPTuHR/PMvZo/zx08ez548fvL50y+yz548mj35/It/v2co3YBsAfU1f56N/s/krFiIydmr88mlAbbG",
	"CS3Z92D2BnVrc0xNiEjN8HKFFWXF6Jn/6X/7K3KaiVU9vP915CpBjpZal+rZycnt7e007nKywOwnEy2q",
	"bHni58Eslo2XyqvzEBFkvf5wR2trE25qyOxnvr3++uKSnL06n9YEM3o2Op2eTh9hJsUSOC3Z6NnoM/wJ",
	"T88S9/0E82efKFeG56QOGk3a+V9jgIx/zMsF5OR+CP/7t+DpoR74KMK5yz/5T2WJMaziPEfichXTR1jx",
	"FV0/EazHp6d+L9yLJhIsTzDW7Nm7keUfqUS4HaRe1gAnIavrTXcX/RO/5uKWE0z2aw9QtVpRubEraGAj",
	"Ghy3iS4UGuUku8GcjKZ3G+dl6Yof9aEc62k2T7nvjAQSKuOYE2YL5rgSRiqF8m7hpTtif2vy585kid3B",
	"Rq8MzD7BWUiY7K5BhzP0MbEIC2fEqik7iB6PyiqBzq8xjE9tw9k4KtZjoRFFHjDeweir6n8IRg3pLkLi",
	"X/PXEmiBcpH5Y2UINfOfJNB84/6vbuliAXLq1ml+unl84rUNJ+9cJqn3276dxP6nJ+8a6bjyHT29B+Wu",
	"JifvXIaqHQPGBpET59kedRgI6LZmJzOstDm0KcSr618K0rw6eYdaud7fT5yQnv6IilN7w574l0dPS5s9",
	"KP2xgcJ3em0Wsn040yYaL6M6W1blyTv8D5JttCKbuf9Er/kJOpqdvGsgwn3uIKL5e909boEJpz1wYj5X",
	"yLS3fT55Z/+NJoJ1CZKtgNti4+5Xm8f2BAtbb7o/b3iW/LG7jka6zh2XOeaHVd77spnlM3l9tFOHqrsy",
	"u2Hpt9oJS7sCdleS2ray9+PRkyNy5WYlgAQwX9Kc+AwrOPejjzf3ObcxJEa0tCIwQvDk40HQ2D7yPWzI",
	"j0KTb7z2/unH3Ilzbl6OtPAC3YGi37Dj075GjewdmvGFFVSEzbrTPGpned4hevuGBKW/FHi79mFspRal",
	"8+qokVY/oRk3SxgPE5u7uX9t8kcvSHCRwyh+3GpZwfs78oSWPyiV+jxhZ0JbKoaVOXtNA9RkStq2t5wd",
	"OZFjfQcJnz/3k9bRWH/xlL94SuApT08/+3jTX4C8YRmQS1iVQlLJig35iYcwv4N53FmeJ7N/N4/+Th43",
	"Hq0nmchhAXziGNhkJvKNq7g3akxwDVZb1hFkTrx2qfFi6OGeXm+Vklbq8JHRszcpNyoXTF1Ws4JlZsFT",
	"r1sqqV5Gqp+QCLnJ/cYxJwuKyjdnk3+cTr54++7p394no6e7gVR1BOLWr4kqMiRnRRXy0ehb4fI9dC+p",
	"SIOjBVG/SbzM8HAzvSG3jOfi9kHAwG8V4N3hUOCnGY1TN80WZXW3zGLtxmBA7gDaBwH6P2zdgkH2r37X",
	"gi3fupVvD1tDQT/VEt5+aM1bSG36nxcvf4wivq1+xbpNYryxPbAY3iUFhi3dUvSbt4Wnv7Kar2KDmQs0",
	"1ZVqlLSd/nX7/nXj3f3G+zYk6bcVazUWm+wyzegGnA4S85M32rvGn05bM7JBK6kk+eZ3QskC65J3r+XZ",
	"hpw/77zZbbf2RfjlBpu27sLEJdcGcSufarODHvayTZAzC1kIHUJ37KL+Eq3/Eq3v9FwffHiGvNiT+rRv",
	"cWDaeYWOfeH/RngkFrpA/4AOKEO0bp/0+B5l47savZQGzxbkgJxEH2wGoDaa/2IRf7GIu7GIbyFxGPHU",
	"OqaRILr9NHxDGQamq8sbjuhe6vDNq4LKKG3CLsX9GY6YfgB/EK7xsdWUSVxZLSVGVzEbVpDYwONqLv9i",
	"eX+xvD8PyzvbzWiagsmddX3XsFnRMmj41LLSubiN/AIQFhsS1LVs2od/+++TW8r0ZC6kqxdH5xpkt7MG",
	"WiCyGSZyjn+tC313vmD18ujHOOFn8tcT2jTVNt0FDOvt69jxJUh9debynkY+04z/XHsqxp5/yPaDz9+b",
	"t4ZlK5A3/kaoHdmenZxg4rKlUPoENV5NJ7f449tAHu/CPeLI5D3ShZBswTgtJs4jZFI7qz2eno7e//8A",
	"AAD//0rsuowXIgEA",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
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
	res := make(map[string]func() ([]byte, error))
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
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
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
