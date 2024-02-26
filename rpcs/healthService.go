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

package rpcs

import (
	"fmt"
	"github.com/algorand/go-algorand/network"
	"net/http"
)

// HealthServiceStatusPath is the path to register HealthService as a handler for when using gorilla/mux
const HealthServiceStatusPath = "/status"

// HealthService is a service that provides health information endpoints for the node
type HealthService struct {
	net           network.GossipNode
	enableService bool
}

// MakeHealthService creates a new HealthService and registers it with the provided network if enabled
func MakeHealthService(net network.GossipNode, enableService bool) HealthService {
	service := HealthService{net: net, enableService: enableService}

	if enableService {
		net.RegisterHTTPHandler(HealthServiceStatusPath, service)
	}

	return service
}

func (h HealthService) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
	_, err := fmt.Fprintf(writer, "Port is Open!")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}
