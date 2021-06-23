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
	"io/ioutil"
	"net/http"
	"net/url"
)

type createDNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      uint   `json:"ttl"`
	Priority uint   `json:"priority"`
	Proxied  bool   `json:"proxied"`
}

// this data structure is based off the following URL:
// https://community.cloudflare.com/t/cloudflare-api-v4-srv-dns-creation-failure-in-php/25677/7
type createSRVRecord struct {
	Type string `json:"type"`
	Data struct {
		Name     string `json:"name"`
		TTL      uint   `json:"ttl"`
		Service  string `json:"service"`
		Proto    string `json:"proto"`
		Weight   uint   `json:"weight"`
		Port     uint   `json:"port"`
		Priority uint   `json:"priority"`
		Target   string `json:"target"`
	} `json:"data"`
}

// createDNSRecordRequest construct a http request that would create a new dns record
func createDNSRecordRequest(zoneID string, authEmail string, authKey string, recordType string, name string, content string, ttl uint, priority uint, proxied bool) (*http.Request, error) {
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
	uri, err := url.Parse(fmt.Sprintf("%szones/%s/dns_records", cloudFlareURI, zoneID))
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", uri.String(), bytes.NewReader(requestBodyBytes))
	if err != nil {
		return nil, err
	}
	addHeaders(request, authEmail, authKey)
	return request, nil
}

// createSRVRecordRequest construct a http request that would create a new dns record
func createSRVRecordRequest(zoneID string, authEmail string, authKey string, name string, service string, protocol string, weight uint, port uint, ttl uint, priority uint, target string) (*http.Request, error) {
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
	uri, err := url.Parse(fmt.Sprintf("%szones/%s/dns_records", cloudFlareURI, zoneID))
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", uri.String(), bytes.NewReader(requestBodyBytes))
	if err != nil {
		return nil, err
	}
	addHeaders(request, authEmail, authKey)
	return request, nil
}

// CreateDNSRecordResponse is the JSON response for a DNS create request
type CreateDNSRecordResponse struct {
	Success  bool                  `json:"success"`
	Errors   []interface{}         `json:"errors"`
	Messages []interface{}         `json:"messages"`
	Result   CreateDNSRecordResult `json:"result"`
}

// CreateDNSRecordResult is the result of the response for the DNS create request
type CreateDNSRecordResult struct {
	ID         string      `json:"id"`
	Type       string      `json:"type"`
	Name       string      `json:"name"`
	Content    string      `json:"content"`
	Proxiable  bool        `json:"proxiable"`
	Proxied    bool        `json:"proxied"`
	TTL        uint        `json:"ttl"`
	Locked     bool        `json:"locked"`
	ZoneID     string      `json:"zone_id"`
	ZoneName   string      `json:"zone_name"`
	CreatedOn  string      `json:"created_on"`
	ModifiedOn string      `json:"modified_on"`
	Data       interface{} `json:"data"`
}

// parseCreateDNSRecordResponse parses the response that was received as a result of a ListDNSRecordRequest
func parseCreateDNSRecordResponse(response *http.Response) (*CreateDNSRecordResponse, error) {
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Response status code %d; body = %s", response.StatusCode, string(body))
	}
	var parsedReponse CreateDNSRecordResponse
	if err := json.Unmarshal(body, &parsedReponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body '%s' : %v", string(body), err)
	}
	return &parsedReponse, nil
}

// clampTTL clamps the input ttl value to the accepted range of 120 - 2147483647 or 1 ( automatic )
// see documentation at https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
func clampTTL(ttl uint) uint {
	if ttl <= AutomaticTTL {
		ttl = AutomaticTTL // automatic.
	}
	if ttl > AutomaticTTL && ttl < 120 {
		ttl = 120
	}
	if ttl > 2147483647 {
		ttl = 2147483647
	}
	return ttl
}

// clampPriority clamps the input priority value to the accepted range of 0..65535
// see documentation at https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
func clampPriority(priority uint) uint {
	if priority < 0 {
		priority = 0
	} else if priority > 65535 {
		priority = 65535
	}
	return priority
}
