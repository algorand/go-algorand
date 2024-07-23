// Copyright (C) 2019-2024 Algorand, Inc.
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

package routes

import (
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/handlers"
)

// V1Routes contains all routes for v1
// v1 algod paths will route to the sunset message, resulting in a 410 Gone response.
var V1Routes = lib.Routes{
	lib.Route{
		Name:        "status",
		Method:      "GET",
		Path:        "/status",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "wait-for-block",
		Method:      "GET",
		Path:        "/status/wait-for-block-after/:round",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "raw-transaction",
		Method:      "POST",
		Path:        "/transactions",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "account-information",
		Method:      "GET",
		Path:        "/account/:addr",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "transaction-information",
		Method:      "GET",
		Path:        "/account/:addr/transaction/:txid",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "suggested-fee",
		Method:      "GET",
		Path:        "/transactions/fee",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "suggested-params",
		Method:      "GET",
		Path:        "/transactions/params",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "transactions",
		Method:      "GET",
		Path:        "/account/:addr/transactions",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "block",
		Method:      "GET",
		Path:        "/block/:round",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "ledger-supply",
		Method:      "GET",
		Path:        "/ledger/supply",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "list-pending-transactions",
		Method:      "GET",
		Path:        "/transactions/pending",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "pending-transaction-information",
		Method:      "GET",
		Path:        "/transactions/pending/:txid",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "pending-transaction-information-by-address",
		Method:      "GET",
		Path:        "/account/:addr/transactions/pending",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "asset-information-by-id",
		Method:      "GET",
		Path:        "/asset/:index",
		HandlerFunc: handlers.V1Sunset,
	},

	lib.Route{
		Name:        "list-assets",
		Method:      "GET",
		Path:        "/assets",
		HandlerFunc: handlers.V1Sunset,
	},

	// ----- This can only be active when indexer is live

	lib.Route{
		Name:        "get-transaction-by-id",
		Method:      "GET",
		Path:        "/transaction/:txid",
		HandlerFunc: handlers.V1Sunset,
	},
}
