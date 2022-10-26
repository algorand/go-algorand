package api

import _ "embed"

// SwaggerSpecJSONEmbed is a string that is pulled from algod.oas2.json via go-embed
// for use with the GET /swagger.json endpoint
//go:embed algod.oas2.json
var SwaggerSpecJSONEmbed string
