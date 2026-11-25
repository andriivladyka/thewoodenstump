// Package api holds the published API description.
package api

import _ "embed"

//go:embed openapi.json
var OpenAPI []byte
