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

package common

import (
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
)

// Routes are routes that are common for all versions
var Routes = lib.Routes{
	lib.Route{
		Method:      "OPTIONS",
		HandlerFunc: optionsHandler,
	},

	lib.Route{
		Name:        "versions",
		Method:      "GET",
		Path:        "/versions",
		HandlerFunc: VersionsHandler,
	},

	lib.Route{
		Name:        "healthcheck",
		Method:      "GET",
		Path:        "/health",
		HandlerFunc: HealthCheck,
	},

	lib.Route{
		Name:        "swagger.json",
		Method:      "GET",
		Path:        "/swagger.json",
		HandlerFunc: SwaggerJSON,
	},

	lib.Route{
		Name:        "genesis",
		Method:      "GET",
		Path:        "/genesis",
		HandlerFunc: GenesisJSON,
	},
}
