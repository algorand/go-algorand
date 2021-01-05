// Copyright (C) 2019-2021 Algorand, Inc.
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

package client

import (
	"net/http"
	"time"
)

const (
	timeoutSecs = 120
)

// APIVersion is used to define which server side API version would be used when making http requests to the server
type APIVersion string

const (
	// APIVersionV1 suggests that the RestClient would use v1 calls whenever it's available for the given request.
	APIVersionV1 APIVersion = "v1"
)

// KMDClient is the client used to interact with the kmd API over its socket
type KMDClient struct {
	httpClient http.Client
	apiToken   string
	address    string
}

func makeHTTPClient() http.Client {
	client := http.Client{
		Timeout: timeoutSecs * time.Second,
	}
	return client
}

// MakeKMDClient instantiates a KMDClient for the given sockFile and apiToken
func MakeKMDClient(address string, apiToken string) (KMDClient, error) {
	kcl := KMDClient{
		httpClient: makeHTTPClient(),
		apiToken:   apiToken,
		address:    address,
	}
	return kcl, nil
}
