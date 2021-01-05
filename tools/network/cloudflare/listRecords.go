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

// listDNSRecordRequest creates a new http request for listing of DNS records.
func listDNSRecordRequest(zoneID string, authEmail string, authKey string, recordType string, name string, content string, page uint, perPage uint, order string, direction string, match string) (*http.Request, error) {
	// verify and validate input parameters.
	if page == 0 {
		page = 1
	}
	if perPage < 5 {
		perPage = 5
	}
	if perPage > 100 {
		perPage = 100
	}
	if direction != "asc" && direction != "desc" {
		direction = ""
	}
	if match != "any" && match != "all" {
		match = "all"
	}

	// build all the arguments
	uriValues := make(url.Values)
	if len(recordType) > 0 {
		uriValues.Add("type", recordType)
	}
	if len(name) > 0 {
		uriValues.Add("name", name)
	}
	if len(content) > 0 {
		uriValues.Add("content", content)
	}
	uriValues.Add("page", fmt.Sprintf("%d", page))
	uriValues.Add("per_page", fmt.Sprintf("%d", perPage))
	if len(order) > 0 {
		uriValues.Add("order", order)
	}
	if len(direction) > 0 {
		uriValues.Add("direction", direction)
	}
	uriValues.Add("match", match)

	// construct the query
	uri, err := url.Parse(fmt.Sprintf("%szones/%s/dns_records?%s", cloudFlareURI, zoneID, uriValues.Encode()))
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("GET", uri.String(), nil)
	if err != nil {
		return nil, err
	}
	addHeaders(request, authEmail, authKey)
	return request, nil
}

// ListDNSRecordError is the JSON data structure for a single error during list dns records request
type ListDNSRecordError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ListDNSRecordResponse is the JSON data structure returned when we list the dns records
type ListDNSRecordResponse struct {
	Result     []DNSRecordResponseEntry    `json:"result"`
	ResultInfo DNSRecordResponseResultInfo `json:"result_info"`
	Errors     []ListDNSRecordError        `json:"errors"`
	Messages   []interface{}               `json:"messages"`
}

// DNSRecordResponseResultInfo is paging status for the returned JSON structure ListDNSRecordResponse
type DNSRecordResponseResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// DNSRecordResponseEntry represent a single returned DNS record entry
type DNSRecordResponseEntry struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	Content    string `json:"content"`
	Proxiable  bool   `json:"proxiable"`
	Proxied    bool   `json:"proxied"`
	TTL        int    `json:"ttl"`
	Priority   int    `json:"priority"`
	Locked     bool   `json:"locked"`
	ZoneID     string `json:"zone_id"`
	ZoneName   string `json:"zone_name"`
	ModifiedOn string `json:"modified_on"`
	CreatedOn  string `json:"created_on"`
}

// parseListDNSRecordResponse parses the reponse that was received as a result of a ListDNSRecordRequest
func parseListDNSRecordResponse(response *http.Response) (*ListDNSRecordResponse, error) {
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var parsedResponse ListDNSRecordResponse
	if err := json.Unmarshal(body, &parsedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body '%s' : %v", string(body), err)
	}
	return &parsedResponse, nil
}
