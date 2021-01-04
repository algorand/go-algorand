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

package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// updateDNSRecordRequest construct a http request that would update an existing dns record
func updateDNSRecordRequest(zoneID string, authEmail string, authKey string, recordID string, recordType string, name string, content string, ttl uint, priority uint, proxied bool) (*http.Request, error) {
	// verify input arguments
	ttl = clampTTL(ttl)
	priority = clampPriority(priority)

	requestJSON := createDNSRecord{
		Type:     recordType,
		Name:     name,
		Content:  content,
		TTL:      ttl,
		Priority: priority,
		Proxied:  proxied,
	}
	requestBodyBytes, err := json.Marshal(requestJSON)
	if err != nil {
		return nil, err
	}
	// construct the query
	uri, err := url.Parse(fmt.Sprintf("%szones/%s/dns_records/%s", cloudFlareURI, zoneID, recordID))
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("PUT", uri.String(), bytes.NewReader(requestBodyBytes))
	if err != nil {
		return nil, err
	}
	addHeaders(request, authEmail, authKey)
	return request, nil
}

// updateSRVRecordRequest construct a http request that would update an existing srv record
func updateSRVRecordRequest(zoneID string, authEmail string, authKey string, recordID string, name string, service string, protocol string, weight uint, port uint, ttl uint, priority uint, target string) (*http.Request, error) {
	// verify input arguments
	ttl = clampTTL(ttl)
	priority = clampPriority(priority)

	requestJSON := createSRVRecord{
		Type: "SRV",
	}
	requestJSON.Data.Name = name
	requestJSON.Data.TTL = ttl
	requestJSON.Data.Service = service
	requestJSON.Data.Proto = protocol
	requestJSON.Data.Weight = weight
	requestJSON.Data.Port = port
	requestJSON.Data.Priority = priority
	requestJSON.Data.Target = target

	requestBodyBytes, err := json.Marshal(requestJSON)
	if err != nil {
		return nil, err
	}
	// construct the query
	uri, err := url.Parse(fmt.Sprintf("%szones/%s/dns_records/%s", cloudFlareURI, zoneID, recordID))
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("PUT", uri.String(), bytes.NewReader(requestBodyBytes))
	if err != nil {
		return nil, err
	}
	addHeaders(request, authEmail, authKey)
	return request, nil
}

// parseUpdateDNSRecordResponse parses the reponse that was received as a result of a ListDNSRecordRequest
func parseUpdateDNSRecordResponse(response *http.Response) (*CreateDNSRecordResponse, error) {
	return parseCreateDNSRecordResponse(response)
}
