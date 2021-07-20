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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// deleteDNSRecordRequest creates a new http request for deleting a single DNS records.
func deleteDNSRecordRequest(zoneID string, authEmail string, authKey string, recordID string) (*http.Request, error) {
	// construct the query
	uri, err := url.Parse(fmt.Sprintf("%szones/%s/dns_records/%s", cloudFlareURI, zoneID, recordID))
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("DELETE", uri.String(), nil)
	if err != nil {
		return nil, err
	}
	addHeaders(request, authEmail, authKey)
	return request, nil
}

// DeleteDNSRecordResponse is the JSON response for a DNS delete request
type DeleteDNSRecordResponse struct {
	Success  bool                  `json:"success"`
	Errors   []interface{}         `json:"errors"`
	Messages []interface{}         `json:"messages"`
	Result   DeleteDNSRecordResult `json:"result"`
}

// DeleteDNSRecordResult is the JSON result for a DNS delete request
type DeleteDNSRecordResult struct {
	ID string `json:"id"`
}

// ParseDeleteDNSRecordResponse parses the response that was received as a result of a ListDNSRecordRequest
func parseDeleteDNSRecordResponse(response *http.Response) (*DeleteDNSRecordResponse, error) {
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var parsedResponse DeleteDNSRecordResponse
	if err := json.Unmarshal(body, &parsedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body '%s' : %v", string(body), err)
	}
	return &parsedResponse, nil
}
